#include "runtime/icmpv4-pmtu.h"
#include <errno.h>

static int output_mtu(void *, uint32_t *);

static int worker_check(struct ker_neighbor_monitor *m)
{
    if (!m || !m->table)
        return -EINVAL;
    if (rte_lcore_id() != m->table->lcore)
        return -EXDEV;
    if (!m->entry || !m->timer.runtime)
        return -EINVAL;
    if (m->busy || m->timer.running || m->timer.scoping ||
        m->timer.runtime->polling || ker_local_irq_disabled())
        return -EBUSY;
    return 0;
}

static int attachment_check(struct ker_icmpv4_pmtu *p)
{
    if (!p || !p->attached || !p->monitor)
        return -EINVAL;
    struct ker_neighbor_monitor *m = p->monitor;
    if (m->output_mtu != output_mtu || m->output_mtu_ctx != p)
        return -ESTALE;
    return worker_check(m);
}

static int read_clock(struct ker_icmpv4_pmtu *p, uint64_t *now)
{
    uint64_t value = p->clock(p->clock_arg);
    if (p->clock_started && value < p->last_now_ms)
        return -ERANGE;
    p->clock_started = true;
    p->last_now_ms = value;
    *now = value;
    return 0;
}

static int refresh(struct ker_icmpv4_pmtu *p, uint64_t *now)
{
    int error = read_clock(p, now);
    if (error)
        return error;
    if (p->current_mtu < p->initial_mtu && *now >= p->expires_ms) {
        p->current_mtu = p->initial_mtu;
        p->expires_ms = 0;
    }
    return 0;
}

static int output_mtu(void *arg, uint32_t *mtu)
{
    struct ker_icmpv4_pmtu *p = arg;
    if (!p || !mtu || !p->attached || p->busy)
        return -EBUSY;
    if (!p->monitor || !p->monitor->table || !p->monitor->timer.runtime)
        return -ESTALE;
    if (rte_lcore_id() != p->monitor->table->lcore)
        return -EXDEV;
    if (p->monitor->output_mtu != output_mtu || p->monitor->output_mtu_ctx != p)
        return -ESTALE;
    if (p->monitor->busy || p->monitor->timer.running || p->monitor->timer.scoping ||
        p->monitor->timer.runtime->polling || ker_local_irq_disabled())
        return -EBUSY;
    p->busy = true;
    p->monitor->busy = true;
    int error = refresh(p, &(uint64_t){0});
    if (!error)
        *mtu = p->current_mtu;
    p->monitor->busy = false;
    p->busy = false;
    return error;
}

int ker_icmpv4_pmtu_init(struct ker_icmpv4_pmtu *p,
    struct ker_neighbor_monitor *m, uint32_t initial_mtu, uint64_t lifetime_ms,
    ker_icmpv4_pmtu_clock_fn clock, void *clock_arg,
    ker_icmpv4_pmtu_confirm_fn confirm, void *confirm_arg)
{
    if (!p || !m || !clock || !confirm || initial_mtu < 68 ||
        initial_mtu > UINT16_MAX || !lifetime_ms)
        return -EINVAL;
    if (p->attached || p->busy)
        return p->attached ? -EALREADY : -EBUSY;
    if (!m->table)
        return -EINVAL;
    if (rte_lcore_id() != m->table->lcore)
        return -EXDEV;
    if (!m->timer.runtime)
        return -EINVAL;
    if (m->busy || m->timer.running || m->timer.scoping ||
        m->timer.runtime->polling || ker_local_irq_disabled())
        return -EBUSY;
    if (!m->table || !m->table->address || !m->table->address->native ||
        !m->table->address->native->ifa_list || !m->entry || !m->entry->dev ||
        initial_mtu > m->entry->dev->mtu)
        return -EINVAL;
    if (m->output_mtu || m->output_mtu_ctx)
        return -EBUSY;
    struct ker_icmpv4_pmtu value = {
        .monitor = m,
        .clock = clock,
        .clock_arg = clock_arg,
        .confirm = confirm,
        .confirm_arg = confirm_arg,
        .local = m->table->address->native->ifa_list->ifa_local,
        .initial_mtu = initial_mtu,
        .current_mtu = initial_mtu,
        .lifetime_ms = lifetime_ms,
    };
    memcpy(&value.peer, m->entry->primary_key, sizeof(value.peer));
    /* Pin both objects against callbacks that reenter lifecycle APIs. */
    p->busy = true;
    m->busy = true;
    uint64_t now = clock(clock_arg);
    value.last_now_ms = now;
    value.clock_started = true;
    value.attached = true;
    m->output_mtu_ctx = p;
    m->output_mtu = output_mtu;
    *p = value;
    m->busy = false;
    return 0;
}

static uint32_t legacy_plateau(uint16_t packet_length)
{
    static const uint16_t plateaus[] = {
        65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68
    };
    for (size_t i = 0; i < sizeof(plateaus) / sizeof(plateaus[0]); ++i)
        if (plateaus[i] < packet_length)
            return plateaus[i];
    return 0;
}

int ker_icmpv4_pmtu_apply(struct ker_icmpv4_pmtu *p,
    const struct ker_icmpv4_packet_view *outer,
    const struct ker_icmpv4_quoted_ipv4_view *quote)
{
    if (!p || !outer || !quote ||
        !outer->header || !quote->header)
        return -EINVAL;
    int error = attachment_check(p);
    if (error)
        return error;
    if (p->busy)
        return -EBUSY;
    if (outer->type != 3 || outer->code != 4)
        return -EINVAL;
    const unsigned char *quoted = outer->quoted_ipv4 ? outer->quoted_ipv4 : outer->payload;
    unsigned int quote_length = outer->quoted_ipv4 ? outer->quoted_length : quote->quoted_length;
    if (!quoted || !quote_length || outer->payload_length < quote_length ||
        quoted != quote->header || quote_length != quote->quoted_length)
        return -EINVAL;
    struct ker_icmpv4_quoted_ipv4_view parsed;
    error = ker_icmpv4_quoted_ipv4_view_init(quoted, quote_length, &parsed);
    if (error)
        return error;
    if (parsed.quoted_length != quote_length)
        return -EINVAL;
    const unsigned char *ip = parsed.header;
    __be32 source, destination;
    memcpy(&source, ip + 12, 4);
    memcpy(&destination, ip + 16, 4);
    if (source != p->local || destination != p->peer)
        return -EACCES;
    uint16_t frag = ((uint16_t)ip[6] << 8) | ip[7];
    if (!(frag & 0x4000U) || !parsed.flow_available || parsed.fragment_offset != 0)
        return -EINVAL;

    uint16_t advertised = ((uint16_t)outer->rest[2] << 8) | outer->rest[3];
    uint32_t candidate = advertised ? advertised : legacy_plateau(parsed.total_length);
    if (candidate < 68 || candidate >= parsed.total_length)
        return -ERANGE;

    p->busy = true;
    p->monitor->busy = true;
    uint64_t now;
    error = refresh(p, &now);
    if (error)
        goto done;
    if (candidate >= p->current_mtu) {
        error = 0;
        goto done;
    }
    int confirmed = p->confirm(p->confirm_arg, p->local, p->peer, &parsed);
    if (confirmed < 0) {
        error = confirmed;
        goto done;
    }
    if (confirmed != 1) {
        error = 0;
        goto done;
    }
    if (now > UINT64_MAX - p->lifetime_ms) {
        error = -ERANGE;
        goto done;
    }
    p->current_mtu = candidate;
    p->expires_ms = now + p->lifetime_ms;
    error = 1;
done:
    p->monitor->busy = false;
    p->busy = false;
    return error;
}

int ker_icmpv4_pmtu_current_mtu(struct ker_icmpv4_pmtu *p, uint32_t *mtu)
{
    if (!p || !mtu)
        return -EINVAL;
    int error = attachment_check(p);
    if (error)
        return error;
    if (p->busy)
        return -EBUSY;
    p->busy = true;
    p->monitor->busy = true;
    error = refresh(p, &(uint64_t){0});
    if (!error)
        *mtu = p->current_mtu;
    p->monitor->busy = false;
    p->busy = false;
    return error;
}

int ker_icmpv4_pmtu_cleanup(struct ker_icmpv4_pmtu *p)
{
    int error = attachment_check(p);
    if (error)
        return error;
    struct ker_neighbor_monitor *m = p->monitor;
    if (p->busy)
        return -EBUSY;
    p->busy = true;
    m->busy = true;
    m->output_mtu = NULL;
    m->output_mtu_ctx = NULL;
    *p = (struct ker_icmpv4_pmtu){0};
    m->busy = false;
    return 0;
}
