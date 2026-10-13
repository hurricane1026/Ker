#include "runtime/flow.h"
#include "runtime/worker.h"
#include <linux/irqflags.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_ring_elem.h>
#include <netinet/in.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

struct flow_envelope {
    struct rte_mbuf *packet;
    struct ker_flow_key key;
    uint16_t owner;
    uint16_t reserved;
};
_Static_assert(sizeof(struct flow_envelope) % 4 == 0, "DPDK ring element size alignment");

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

/* Ethernet (14) + maximum IPv4 header (60) + minimum TCP header (20). */
#define FLOW_PREFIX_SIZE 94U

/* Validate the complete topology before following segment data pointers. The
 * walk is bounded by the head's count. */
static int packet_geometry(const struct rte_mbuf *head, size_t *length)
{
    if (!head || !length || !head->nb_segs) return -EINVAL;
    uint16_t count = head->nb_segs;
    const struct rte_mbuf *segment = head;
    uint64_t total = 0;
    for (uint16_t i = 0; i < count; ++i) {
        if (!segment) return -EINVAL;
        if (!segment->buf_addr ||
            (uint64_t)segment->data_off + segment->data_len > segment->buf_len)
            return -EINVAL;
        total += segment->data_len;
        if (total > UINT32_MAX) return -EOVERFLOW;
        segment = segment->next;
    }
    if (segment || total != head->pkt_len) return -EINVAL;
    *length = (size_t)total;
    return 0;
}

static size_t copy_prefix(const struct rte_mbuf *head, uint8_t *prefix, size_t limit)
{
    size_t copied = 0;
    for (const struct rte_mbuf *segment = head; segment && copied < limit; segment = segment->next) {
        size_t amount = segment->data_len;
        if (amount > limit - copied) amount = limit - copied;
        if (amount) {
            memcpy(prefix + copied, rte_pktmbuf_mtod(segment, const uint8_t *), amount);
            copied += amount;
        }
    }
    return copied;
}

static bool key_valid(const struct ker_flow_key *key)
{
    if (!key || (key->family != 4 && key->family != 6) ||
        (key->protocol != IPPROTO_TCP && key->protocol != IPPROTO_UDP))
        return false;
    if (key->family == 4) {
        for (unsigned int i = 0; i < 12; ++i)
            if (key->local[i] || key->remote[i]) return false;
    }
    return true;
}

static int parse_packet(const struct rte_mbuf *packet, uint64_t domain,
    enum ker_flow_direction direction, struct ker_flow_key *out)
{
    if (!packet || !out || (direction != KER_FLOW_INGRESS && direction != KER_FLOW_EGRESS)) return -EINVAL;
    if (packet->ol_flags & (RTE_MBUF_F_RX_VLAN_STRIPPED | RTE_MBUF_F_RX_QINQ_STRIPPED |
        RTE_MBUF_F_TX_VLAN | RTE_MBUF_F_TX_QINQ)) return -ENOTSUP;
    size_t length;
    int geometry_error = packet_geometry(packet, &length);
    if (geometry_error) return geometry_error;
    uint8_t prefix[FLOW_PREFIX_SIZE];
    const uint8_t *data;
    size_t prefix_length;
    if (packet->nb_segs == 1) {
        data = rte_pktmbuf_mtod(packet, const uint8_t *);
        prefix_length = packet->data_len;
    } else {
        prefix_length = copy_prefix(packet, prefix, sizeof(prefix));
        data = prefix;
    }
    if (length < 14) return -EMSGSIZE;
    uint16_t ethertype = be16(data + 12);
    if (ethertype == RTE_ETHER_TYPE_VLAN || ethertype == RTE_ETHER_TYPE_QINQ)
        return -ENOTSUP;

    struct ker_flow_key key = {.domain = domain};
    const uint8_t *ip;
    size_t ip_length;
    size_t transport_offset;
    size_t ip_header_length;
    if (ethertype == RTE_ETHER_TYPE_IPV4) {
        if (length < 14 + 20) return -EMSGSIZE;
        if (prefix_length < 14 + 20) return -EMSGSIZE;
        ip = data + 14;
        if ((ip[0] >> 4) != 4 || (ip[0] & 0x0f) < 5) return -EINVAL;
        ip_header_length = (size_t)(ip[0] & 0x0f) * 4;
        ip_length = be16(ip + 2);
        if (ip_length < ip_header_length) return -EINVAL;
        if (14 + ip_header_length > length) return -EMSGSIZE;
        if (14 + ip_header_length > prefix_length) return -EMSGSIZE;
        if (14 + ip_length > length) return -EMSGSIZE;
        uint16_t fragment = be16(ip + 6);
        if (fragment & 0x3fff) return -ENOTSUP;
        key.family = 4;
        key.protocol = ip[9];
        memcpy(key.local + 12, ip + (direction == KER_FLOW_INGRESS ? 16 : 12), 4);
        memcpy(key.remote + 12, ip + (direction == KER_FLOW_INGRESS ? 12 : 16), 4);
        transport_offset = 14 + ip_header_length;
    } else if (ethertype == RTE_ETHER_TYPE_IPV6) {
        if (length < 14 + 40) return -EMSGSIZE;
        if (prefix_length < 14 + 40) return -EMSGSIZE;
        ip = data + 14;
        if ((ip[0] >> 4) != 6) return -EINVAL;
        ip_length = 40U + be16(ip + 4);
        if (14 + ip_length > length) return -EMSGSIZE;
        key.family = 6;
        key.protocol = ip[6];
        if (key.protocol != IPPROTO_TCP && key.protocol != IPPROTO_UDP)
            return -ENOTSUP; /* Includes all IPv6 extension headers. */
        memcpy(key.local, ip + (direction == KER_FLOW_INGRESS ? 24 : 8), 16);
        memcpy(key.remote, ip + (direction == KER_FLOW_INGRESS ? 8 : 24), 16);
        transport_offset = 14 + 40;
        ip_header_length = 40;
    } else {
        return -ENOTSUP;
    }
    if (key.protocol != IPPROTO_TCP && key.protocol != IPPROTO_UDP)
        return -ENOTSUP;
    size_t transport_length = ip_length - ip_header_length;
    size_t minimum = key.protocol == IPPROTO_TCP ? 20 : 8;
    if (transport_length < minimum) return -EINVAL;
    if (prefix_length < transport_offset + minimum) return -EMSGSIZE;
    const uint8_t *transport = data + transport_offset;
    size_t header_length;
    if (key.protocol == IPPROTO_TCP) {
        header_length = (size_t)(transport[12] >> 4) * 4;
        if (header_length < 20 || header_length > transport_length) return -EINVAL;
    } else {
        header_length = 8;
        uint16_t udp_length = be16(transport + 4);
        if (udp_length < 8 || udp_length > transport_length) return -EINVAL;
    }
    uint16_t src = be16(transport), dst = be16(transport + 2);
    key.local_port = direction == KER_FLOW_INGRESS ? dst : src;
    key.remote_port = direction == KER_FLOW_INGRESS ? src : dst;
    *out = key;
    return 0;
}

int ker_flow_parse(const struct rte_mbuf *packet, uint64_t domain,
    enum ker_flow_direction direction, struct ker_flow_key *key)
{
    if (!key) return -EINVAL;
    struct ker_flow_key parsed;
    int error = parse_packet(packet, domain, direction, &parsed);
    if (!error) *key = parsed;
    return error;
}

int ker_flow_hash(const struct ker_flow_key *key, uint64_t seed, uint32_t *hash)
{
    if (!hash || !key_valid(key)) return -EINVAL;
    uint8_t serialized[46];
    size_t n = 0;
    for (int shift = 56; shift >= 0; shift -= 8) serialized[n++] = (uint8_t)(key->domain >> shift);
    serialized[n++] = key->family;
    serialized[n++] = key->protocol;
    memcpy(serialized + n, key->local, 16); n += 16;
    memcpy(serialized + n, key->remote, 16); n += 16;
    serialized[n++] = (uint8_t)(key->local_port >> 8); serialized[n++] = (uint8_t)key->local_port;
    serialized[n++] = (uint8_t)(key->remote_port >> 8); serialized[n++] = (uint8_t)key->remote_port;
    /* Seeded FNV-1a followed by a fixed avalanche; byte serialization makes
     * the result independent of host structure padding and byte order. */
    uint64_t h = UINT64_C(14695981039346656037) ^ seed;
    for (size_t i = 0; i < n; ++i) h = (h ^ serialized[i]) * UINT64_C(1099511628211);
    h ^= h >> 30; h *= UINT64_C(0xbf58476d1ce4e5b9);
    h ^= h >> 27; h *= UINT64_C(0x94d049bb133111eb);
    h ^= h >> 31;
    *hash = (uint32_t)(h ^ (h >> 32));
    return 0;
}

static bool same_key(const struct ker_flow_key *a, const struct ker_flow_key *b)
{
    return a->domain == b->domain && a->family == b->family && a->protocol == b->protocol &&
        a->local_port == b->local_port && a->remote_port == b->remote_port &&
        !memcmp(a->local, b->local, 16) && !memcmp(a->remote, b->remote, 16);
}

static int config_valid(const struct ker_flow_config *config)
{
    if (!config || !config->worker_count || config->worker_count > KER_FLOW_MAX_WORKERS ||
        !config->bucket_owner || !config->inbox_capacity || config->inbox_capacity > INT_MAX ||
        !config->name || !*config->name ||
        config->special_count > KER_FLOW_MAX_SPECIAL ||
        (config->special_count && !config->special)) return -EINVAL;
    for (unsigned int i = 0; i < KER_FLOW_BUCKETS; ++i)
        if (config->bucket_owner[i] >= config->worker_count) return -EINVAL;
    for (unsigned int i = 0; i < config->special_count; ++i) {
        if (!key_valid(&config->special[i].key) || config->special[i].owner >= config->worker_count)
            return -EINVAL;
        for (unsigned int j = 0; j < i; ++j)
            if (same_key(&config->special[i].key, &config->special[j].key)) return -EEXIST;
    }
    return 0;
}

int ker_flow_fabric_init(struct ker_flow_fabric *fabric, const struct ker_flow_config *config)
{
    if (!fabric) return -EINVAL;
    if (fabric->initialized) return -EALREADY;
    int error = config_valid(config);
    if (error) return error;
    struct rte_ring **rings = rte_zmalloc(NULL, sizeof(*rings) * config->worker_count, RTE_CACHE_LINE_SIZE);
    atomic_bool *attached = rte_zmalloc(NULL, sizeof(*attached) * config->worker_count, RTE_CACHE_LINE_SIZE);
    struct ker_flow_special *special = config->special_count ?
        rte_malloc(NULL, sizeof(*special) * config->special_count, RTE_CACHE_LINE_SIZE) : NULL;
    if (!rings || !attached || (config->special_count && !special)) {
        rte_free(rings); rte_free(attached); rte_free(special); return -ENOMEM;
    }
    if (config->special_count) memcpy(special, config->special, sizeof(*special) * config->special_count);
    char name[RTE_RING_NAMESIZE];
    unsigned int made = 0;
    for (; made < config->worker_count; ++made) {
        int n = snprintf(name, sizeof(name), "%s_%u", config->name, made);
        if (n < 0 || (size_t)n >= sizeof(name)) { error = -ENAMETOOLONG; break; }
        rings[made] = rte_ring_create_elem(name, sizeof(struct flow_envelope), config->inbox_capacity,
            config->socket_id, RING_F_EXACT_SZ | RING_F_SC_DEQ);
        if (!rings[made]) { error = rte_errno ? -rte_errno : -ENOMEM; break; }
        atomic_init(&attached[made], false);
    }
    if (made != config->worker_count) {
        while (made) rte_ring_free(rings[--made]);
        rte_free(rings); rte_free(attached); rte_free(special);
        return error ? error : -ENOMEM;
    }
    *fabric = (struct ker_flow_fabric){.worker_count = config->worker_count,
        .inbox = rings, .attached = attached, .special = special,
        .special_count = config->special_count, .seed = config->seed, .initialized = true};
    memcpy(fabric->bucket_owner, config->bucket_owner, sizeof(fabric->bucket_owner));
    return 0;
}

int ker_flow_attach(struct ker_flow_context *context, struct ker_flow_fabric *fabric,
    struct ker_worker *worker, unsigned int worker_id, ker_flow_receive_fn receive, void *arg)
{
    if (!context || !fabric || !fabric->initialized || !worker || !worker->initialized ||
        worker_id >= fabric->worker_count || !receive || !worker->config.handoff_budget) return -EINVAL;
    if (rte_lcore_id() != worker->lcore) return -EXDEV;
    if (worker->polling || ker_local_irq_disabled()) return -EBUSY;
    if (worker->flow || context->attached) return -EALREADY;
    /* Attachment setup is performed serially before the external start barrier. */
    bool expected = false;
    if (!atomic_compare_exchange_strong(&fabric->attached[worker_id], &expected, true)) return -EEXIST;
    context->fabric = fabric; context->worker = worker; context->inbox = fabric->inbox[worker_id];
    memcpy(context->bucket_owner, fabric->bucket_owner, sizeof(context->bucket_owner));
    if (fabric->special_count) {
        context->special = rte_malloc(NULL, sizeof(*context->special) * fabric->special_count, RTE_CACHE_LINE_SIZE);
        if (!context->special) {
            atomic_store(&fabric->attached[worker_id], false);
            *context = (struct ker_flow_context){0};
            return -ENOMEM;
        }
        memcpy(context->special, fabric->special, sizeof(*context->special) * fabric->special_count);
    }
    context->special_count = fabric->special_count;
    context->seed = fabric->seed;
    context->worker_id = worker_id; context->lcore = rte_lcore_id();
    context->receive = receive; context->arg = arg; context->attached = true;
    worker->flow = context;
    return 0;
}

int ker_flow_owner(const struct ker_flow_context *context, const struct ker_flow_key *key,
    unsigned int *owner)
{
    if (!context || !context->attached || !key_valid(key) || !owner) return -EINVAL;
    if (rte_lcore_id() != context->lcore) return -EXDEV;
    for (unsigned int i = 0; i < context->special_count; ++i) {
        if (same_key(key, &context->special[i].key)) { *owner = context->special[i].owner; return 0; }
    }
    uint32_t hash;
    int error = ker_flow_hash(key, context->seed, &hash);
    if (!error) *owner = context->bucket_owner[hash & (KER_FLOW_BUCKETS - 1)];
    return error;
}

int ker_flow_submit(struct ker_flow_context *context, uint64_t domain,
    enum ker_flow_direction direction, struct rte_mbuf **packet)
{
    if (!context || !context->attached || !packet || !*packet) return -EINVAL;
    if (rte_lcore_id() != context->lcore) return -EXDEV;
    if (context->delivering || ker_local_irq_disabled()) return -EBUSY;
    struct ker_flow_key key;
    int error = ker_flow_parse(*packet, domain, direction, &key);
    if (error) return error;
    unsigned int owner;
    error = ker_flow_owner(context, &key, &owner);
    if (error) return error;
    if (owner == context->worker_id) {
        context->delivering = true;
        context->receive(context->arg, &key, *packet);
        context->delivering = false;
        *packet = NULL;
        return 0;
    }
    if (!atomic_load(&context->fabric->attached[owner])) return -ESHUTDOWN;
    struct flow_envelope envelope = {.packet = *packet, .key = key, .owner = (uint16_t)owner};
    if (rte_ring_mp_enqueue_elem(context->fabric->inbox[owner], &envelope, sizeof(envelope)) != 0)
        return -ENOBUFS;
    *packet = NULL;
    return 0;
}

int ker_flow_poll(struct ker_flow_context *context, unsigned int budget)
{
    if (!context || !context->attached) return -EINVAL;
    if (rte_lcore_id() != context->lcore) return -EXDEV;
    if (context->delivering || ker_local_irq_disabled()) return -EBUSY;
    if (budget > INT_MAX) return -EINVAL;
    unsigned int done = 0;
    while (done < budget) {
        struct flow_envelope envelope;
        if (rte_ring_sc_dequeue_elem(context->inbox, &envelope, sizeof(envelope)) != 0) break;
        if (!envelope.packet || envelope.owner != context->worker_id) {
            if (envelope.packet) rte_pktmbuf_free(envelope.packet);
            return -EPROTO;
        }
        unsigned int resolved;
        int error = ker_flow_owner(context, &envelope.key, &resolved);
        if (error || resolved != context->worker_id) {
            rte_pktmbuf_free(envelope.packet);
            return error ? error : -EPROTO;
        }
        context->delivering = true;
        context->receive(context->arg, &envelope.key, envelope.packet);
        context->delivering = false;
        ++done;
    }
    return (int)done;
}

int ker_flow_detach(struct ker_flow_context *context)
{
    if (!context) return -EINVAL;
    if (!context->attached) return 0;
    if (rte_lcore_id() != context->lcore) return -EXDEV;
    if (context->worker->polling || context->delivering) return -EBUSY;
    if (ker_local_irq_disabled()) return -EBUSY;
    if (!rte_ring_empty(context->inbox)) return -EBUSY;
    context->worker->flow = NULL;
    atomic_store(&context->fabric->attached[context->worker_id], false);
    rte_free(context->special);
    *context = (struct ker_flow_context){0};
    return 0;
}

int ker_flow_fabric_cleanup(struct ker_flow_fabric *fabric)
{
    if (!fabric) return -EINVAL;
    if (!fabric->initialized) return 0;
    for (unsigned int i = 0; i < fabric->worker_count; ++i)
        if (atomic_load(&fabric->attached[i]) || !rte_ring_empty(fabric->inbox[i])) return -EBUSY;
    for (unsigned int i = 0; i < fabric->worker_count; ++i) rte_ring_free(fabric->inbox[i]);
    rte_free(fabric->inbox); rte_free(fabric->attached); rte_free(fabric->special);
    *fabric = (struct ker_flow_fabric){0};
    return 0;
}
