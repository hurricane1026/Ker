#include "check.h"
#include "eal.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include "runtime/skb-queue.h"
#include "runtime/transport-receive.h"
#include "runtime/udp-create.h"
#include "runtime/tcp-create.h"
#include "runtime/worker.h"
#include "runtime/tx-export.h"
#include <errno.h>
#include <net/checksum.h>
#include <pthread.h>
#include <limits.h>
#include <string.h>

#define POOL_COUNT 255U
#define TEST_IPPROTO_TCP 6U
#define TEST_IPPROTO_UDP 17U
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_transport_receiver receiver;
static struct ker_worker worker;
static struct rte_mbuf *pending_chain;
static struct ker_tx_export tx_export;
static bool tx_reject_once;
static bool tx_discard_none_copy;
static int tx_sink_error;
static enum ker_transport_protocol expected_protocol;
static const unsigned char source_mac[6] = {2, 1, 2, 3, 4, 5};
static const unsigned char destination_mac[6] = {2, 6, 7, 8, 9, 10};
static const __be32 source_ip = (__be32)0x010200c0;
static const __be32 destination_ip = (__be32)0x026433c6;
static const __be16 source_port = (__be16)0x3412;
static const __be16 destination_port = (__be16)0x7856;
static unsigned char expected_payload[16];
static unsigned int expected_payload_length, received;

struct foreign_call { struct sk_buff *skb; int error; };
struct foreign_tx_call { struct ker_tx_export *tx; struct sk_buff *skb; int error; };
static void *foreign_worker_call(void *arg)
{
    struct foreign_call *call = arg;
    struct rte_mbuf *out = (void *)(uintptr_t)1;
    call->error = ker_skb_to_mbuf_chain_software_checksum(call->skb, 2, &out);
    CHECK(out == (void *)(uintptr_t)1);
    return NULL;
}
static void *foreign_tx_enqueue(void *arg)
{
    struct foreign_tx_call *call = arg;
    struct sk_buff *skb = call->skb;
    call->error = ker_tx_export_enqueue(call->tx, &skb);
    CHECK(skb == call->skb);
    return NULL;
}

static uint16_t oracle_checksum(const uint8_t *bytes, size_t length, uint32_t sum)
{
    size_t i = 0;
    while (i + 1 < length) {
        sum += ((uint32_t)bytes[i] << 8) | bytes[i + 1];
        i += 2;
    }
    if (i < length) sum += (uint32_t)bytes[i] << 8;
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)~sum;
}

static int receive_packet(const struct ker_transport_message *message, void *arg)
{
    CHECK(arg == &receiver && worker.polling && !worker.timers.polling);
    CHECK(message->protocol == expected_protocol);
    if (expected_protocol == KER_TRANSPORT_UDP) {
        CHECK(message->packet.udp.source_port == source_port &&
            message->packet.udp.destination_port == destination_port);
        CHECK(message->packet.udp.payload_length == expected_payload_length);
        CHECK(!memcmp(message->packet.udp.payload, expected_payload, expected_payload_length));
    } else {
        CHECK(message->packet.tcp.source_port == source_port &&
            message->packet.tcp.destination_port == destination_port);
        CHECK(message->packet.tcp.payload_length == expected_payload_length);
        CHECK(!memcmp(message->packet.tcp.payload, expected_payload, expected_payload_length));
    }
    received++;
    return NET_RX_SUCCESS;
}

static int rx_poll(void *arg, unsigned int budget)
{
    (void)arg;
    CHECK(budget == 1);
    if (!pending_chain) return 0;
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, pending_chain, 128, &skb) == 0);
    ker_packet_free(pending_chain);
    pending_chain = NULL;
    struct ker_receive_result result = {0};
    CHECK(ker_receive_dispatch(&runtime, &device, &skb, &result) == 0 && !skb);
    CHECK(result.handlers == 1 && result.status == NET_RX_SUCCESS);
    return 1;
}

static struct sk_buff *make_partial(bool tcp, const uint8_t *payload, unsigned int payload_len)
{
    struct sk_buff *skb = NULL;
    if (tcp) {
        CHECK(ker_tcp_ipv4_create(&context, source_mac, destination_mac, source_ip,
            destination_ip, source_port, destination_port, (__be32)0x01020304,
            (__be32)0x05060708, (__be16)4096, 0x18, 64, payload, payload_len, &skb) == 0);
    } else {
        CHECK(ker_udp_ipv4_create(&context, source_mac, destination_mac, source_ip,
            destination_ip, source_port, destination_port, 64, payload, payload_len, &skb) == 0);
    }
    unsigned int start = ETH_HLEN + 20;
    unsigned int field = tcp ? 16 : 6;
    unsigned int l4_length = skb->len - start;
    __wsum pseudo = csum_tcpudp_nofold(source_ip, destination_ip, l4_length,
        tcp ? TEST_IPPROTO_TCP : TEST_IPPROTO_UDP, 0);
    __sum16 seed = (__sum16)~csum_fold(pseudo);
    CHECK(seed != 0);
    memcpy(skb->data + start + field, &seed, sizeof(seed));
    skb->ip_summed = CHECKSUM_PARTIAL;
    skb->csum_start = (uint16_t)(skb_headroom(skb) + start);
    skb->csum_offset = (uint16_t)field;
    return skb;
}

static void verify_ipv4_transport_checksum(const struct rte_mbuf *chain, bool tcp)
{
    uint8_t frame[256];
    CHECK(chain->pkt_len <= sizeof(frame));
    size_t offset = 0;
    for (const struct rte_mbuf *seg = chain; seg; seg = seg->next) {
        CHECK(RTE_MBUF_DIRECT(seg) && !RTE_MBUF_HAS_EXTBUF(seg) && seg->ol_flags == 0);
        CHECK(offset + seg->data_len <= sizeof(frame));
        memcpy(frame + offset, rte_pktmbuf_mtod(seg, const void *), seg->data_len);
        offset += seg->data_len;
    }
    CHECK(offset == chain->pkt_len);
    uint8_t *ip = frame + ETH_HLEN;
    uint8_t *l4 = ip + 20;
    unsigned int l4len = (unsigned int)(chain->pkt_len - ETH_HLEN - 20);
    unsigned int field = tcp ? 16 : 6;
    uint8_t pseudo[12];
    memcpy(pseudo, ip + 12, 8);
    pseudo[8] = 0; pseudo[9] = tcp ? TEST_IPPROTO_TCP : TEST_IPPROTO_UDP;
    pseudo[10] = (uint8_t)(l4len >> 8); pseudo[11] = (uint8_t)l4len;
    uint8_t l4zero[220];
    CHECK(l4len <= sizeof(l4zero));
    memcpy(l4zero, l4, l4len);
    l4zero[field] = 0; l4zero[field + 1] = 0;
    /* Compute the complete pseudoheader+transport sum in one independent pass. */
    uint8_t full[232];
    memcpy(full, pseudo, sizeof(pseudo));
    memcpy(full + sizeof(pseudo), l4zero, l4len);
    uint16_t expected = oracle_checksum(full, sizeof(pseudo) + l4len, 0);
    if (!tcp && !expected) expected = UINT16_MAX;
    CHECK(l4[field] == (uint8_t)(expected >> 8) && l4[field + 1] == (uint8_t)expected);
}

static int tx_sink(struct rte_mbuf *chain, void *arg)
{
    CHECK(arg == &tx_export && chain && chain->nb_segs > 1);
    if (tx_discard_none_copy) {
        for (struct rte_mbuf *segment = chain; segment; segment = segment->next)
            CHECK(segment->ol_flags == 0);
        tx_discard_none_copy = false;
        ker_packet_free(chain);
        return 0;
    }
    verify_ipv4_transport_checksum(chain, expected_protocol == KER_TRANSPORT_TCP);
    if (tx_reject_once) { tx_reject_once = false; return -EAGAIN; }
    if (tx_sink_error) return tx_sink_error;
    CHECK(!pending_chain);
    pending_chain = chain;
    return 0;
}

static void tx_chain_checksum_retry(void)
{
    static const uint8_t payload[] = {0x10, 0x23, 0x45, 0x67, 0x89};
    memcpy(expected_payload, payload, sizeof(payload));
    expected_payload_length = sizeof(payload);
    expected_protocol = KER_TRANSPORT_UDP;
    struct sk_buff *skb = make_partial(false, payload, sizeof(payload));
    uint8_t original[128]; CHECK(skb->len <= sizeof(original));
    memcpy(original, skb->data, skb->len);
    CHECK(ker_tx_export_init_chain_software_checksum(&tx_export, &context,
        2, SIZE_MAX, 2, tx_sink, &tx_export) == 0);
    struct sk_buff *unsupported = make_partial(false, payload, sizeof(payload));
    unsupported->ip_summed = 2U; /* Native CHECKSUM_COMPLETE enum value. */
    CHECK(ker_tx_export_enqueue(&tx_export, &unsupported) == -ENOTSUP && unsupported);
    CHECK(ker_skb_free(unsupported) == 0);
    struct sk_buff *none = NULL; uint8_t *none_data = NULL;
    CHECK(ker_skb_alloc(&context, 32, 64, &none) == 0);
    CHECK(ker_skb_put(none, 32, &none_data) == 0);
    memset(none_data, 0x5a, 32);
    tx_discard_none_copy = true;
    CHECK(ker_tx_export_enqueue(&tx_export, &none) == 0 && !none);
    struct sk_buff *held_skb = skb;
    CHECK(ker_tx_export_enqueue(&tx_export, &skb) == 0 && !skb);
    CHECK(held_skb && context.live == 2 && !memcmp(held_skb->data, original, held_skb->len));

    CHECK(ker_tx_export_poll(&tx_export, 1) == 1 && !tx_export.pending &&
        tx_export.packets == 1 && context.live == 1 && !pending_chain);
    struct rte_mbuf *held[POOL_COUNT]; unsigned int held_count = 0;
    const unsigned int available_prefixes[] = {0, 5, 11};
    for (unsigned int trial = 0; trial < 3; ++trial) {
        while (held_count < POOL_COUNT &&
            (held[held_count] = ker_packet_alloc(&pool)) != NULL) held_count++;
        CHECK(held_count > 12 && rte_mempool_avail_count(pool.mbufs) == 0);
        unsigned int give = available_prefixes[trial];
        while (give--) ker_packet_free(held[--held_count]);
        CHECK(ker_tx_export_poll(&tx_export, 1) == -ENOMEM);
        CHECK(tx_export.pending == held_skb && tx_export.packets == 1 &&
            tx_export.bytes == held_skb->truesize &&
            !memcmp(held_skb->data, original, held_skb->len));
        while (held_count) ker_packet_free(held[--held_count]);
    }

    tx_reject_once = true;
    CHECK(ker_tx_export_poll(&tx_export, 1) == -EAGAIN);
    CHECK(tx_export.pending == held_skb && context.live == 1 && !pending_chain);
    CHECK(!memcmp(held_skb->data, original, held_skb->len));
    CHECK(ker_tx_export_poll(&tx_export, 1) == 1);
    CHECK(!tx_export.pending && !tx_export.packets && !tx_export.bytes &&
        context.live == 0 && pending_chain);
    struct ker_worker_result progress = {0};
    unsigned int before = received;
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
    CHECK(progress.rx == 1 && received == before + 1 && !pending_chain && context.live == 0);
    CHECK(ker_tx_export_cleanup(&tx_export) == 0);
}

static void tx_chain_tcp_checksum_cancel(void)
{
    static const uint8_t payload[] = {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x17};
    memcpy(expected_payload, payload, sizeof(payload));
    expected_payload_length = sizeof(payload);
    expected_protocol = KER_TRANSPORT_TCP;
    struct sk_buff *skb = make_partial(true, payload, sizeof(payload));
    uint8_t original[128]; CHECK(skb->len <= sizeof(original));
    memcpy(original, skb->data, skb->len);
    CHECK(ker_tx_export_init_chain_software_checksum(&tx_export, &context,
        1, SIZE_MAX, 1, tx_sink, &tx_export) == 0);

    uint16_t saved_start = skb->csum_start;
    unsigned int users = refcount_read(&skb->users);
    CHECK(ker_skb_get(skb) == 0);
    struct sk_buff *same = skb;
    CHECK(ker_tx_export_enqueue(&tx_export, &same) == -ENOTSUP && same == skb);
    CHECK(refcount_read(&skb->users) == users + 1 && ker_skb_free(skb) == 0);
    struct foreign_tx_call foreign_tx = {.tx = &tx_export, .skb = skb};
    pthread_t tx_thread;
    CHECK(pthread_create(&tx_thread, NULL, foreign_tx_enqueue, &foreign_tx) == 0);
    CHECK(pthread_join(tx_thread, NULL) == 0 && foreign_tx.error == -EXDEV);
    skb->csum_start = 0;
    same = skb;
    CHECK(ker_tx_export_enqueue(&tx_export, &same) == -EINVAL && same == skb);
    skb->csum_start = saved_start;
    skb_shinfo(skb)->gso_size = 1;
    CHECK(ker_tx_export_enqueue(&tx_export, &same) == -ENOTSUP && same == skb);
    skb_shinfo(skb)->gso_size = 0;
    skb->nohdr = 1;
    CHECK(ker_tx_export_enqueue(&tx_export, &same) == -ENOTSUP && same == skb);
    skb->nohdr = 0;
#if defined(CONFIG_IP_SCTP) || defined(CONFIG_IP_SCTP_MODULE)
    skb->csum_not_inet = 1;
    CHECK(ker_tx_export_enqueue(&tx_export, &same) == -ENOTSUP && same == skb);
    skb->csum_not_inet = 0;
#endif
    CHECK(ker_tx_export_enqueue(&tx_export, &same) == 0 && !same);
    struct sk_buff *returned = (void *)(uintptr_t)1;
    CHECK(ker_tx_export_cancel(&tx_export, &returned) == 1 && returned == skb);
    CHECK(!tx_export.packets && !tx_export.bytes && !tx_export.pending &&
        !memcmp(skb->data, original, skb->len));
    same = skb;
    CHECK(ker_tx_export_enqueue(&tx_export, &same) == 0 && !same);
    tx_sink_error = 1;
    CHECK(ker_tx_export_poll(&tx_export, 1) == -EPROTO && tx_export.pending == skb);
    CHECK(tx_export.last_error == -EPROTO && context.live == 1);
    CHECK(!memcmp(skb->data, original, skb->len) && context.live == 1);
    tx_sink_error = 0;
    CHECK(!memcmp(skb->data, original, skb->len));
    CHECK(ker_tx_export_poll(&tx_export, 1) == 1 && !tx_export.pending && pending_chain);
    CHECK(context.live == 0);
    struct ker_worker_result progress = {0};
    unsigned int before = received;
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
    CHECK(progress.rx == 1 && received == before + 1 && !pending_chain && context.live == 0);
    CHECK(ker_tx_export_cleanup(&tx_export) == 0);
}

static void actual_udp_tcp_roundtrip(void)
{
    static const uint8_t udp_payload[] = {1, 3, 5, 7, 9};
    static const uint8_t tcp_payload[] = {2, 4, 6, 8, 10, 12};
    const uint8_t *payload = udp_payload;
    unsigned int length = sizeof(udp_payload);
    for (unsigned int type = 0; type < 2; ++type) {
        bool tcp = type != 0;
        if (tcp) { payload = tcp_payload; length = sizeof(tcp_payload); }
        memcpy(expected_payload, payload, length);
        expected_payload_length = length;
        expected_protocol = tcp ? KER_TRANSPORT_TCP : KER_TRANSPORT_UDP;
        struct sk_buff *skb = make_partial(tcp, payload, length);
        uint8_t original[128];
        CHECK(skb->len <= sizeof(original));
        memcpy(original, skb->data, skb->len);
        struct rte_mbuf *chain = (void *)(uintptr_t)1;
        CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 1, &chain) == 0);
        CHECK(chain != (void *)(uintptr_t)1 && chain->nb_segs == chain->pkt_len);
        CHECK(skb->ip_summed == CHECKSUM_PARTIAL &&
            skb->csum_start == (uint16_t)(skb_headroom(skb) + ETH_HLEN + 20) &&
            skb->csum_offset == (tcp ? 16U : 6U));
        CHECK(!memcmp(skb->data, original, skb->len));
        verify_ipv4_transport_checksum(chain, tcp);
        CHECK(ker_skb_free(skb) == 0);
        pending_chain = chain;
        struct ker_worker_result progress = {0};
        CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
        CHECK(progress.rx == 1 && !pending_chain && received == type + 1);
        CHECK(context.live == 0);
    }
}

static void rollback_and_synthetic(void)
{
    struct sk_buff *skb = NULL;
    uint8_t *data = NULL;
    CHECK(ker_skb_alloc(&context, 96, 64, &skb) == 0);
    CHECK(ker_skb_put(skb, 96, &data) == 0);
    for (unsigned int i = 0; i < skb->len; i++) data[i] = (uint8_t)(i * 17U + 3U);
    /* Odd start and odd field offset exercise a checksum word split by limit 2. */
    skb->ip_summed = CHECKSUM_PARTIAL;
    skb->csum_start = (uint16_t)(skb_headroom(skb) + 1);
    skb->csum_offset = 2;
    bool folded_zero = false;
    for (uint32_t value = 0; value <= UINT16_MAX; ++value) {
        __sum16 seed = (__sum16)value;
        memcpy(skb->data + 3, &seed, sizeof(seed));
        if (!csum_fold(csum_partial(skb->data + 1, skb->len - 1, 0))) {
            folded_zero = true;
            break;
        }
    }
    CHECK(folded_zero);
    uint8_t before[96]; memcpy(before, skb->data, sizeof(before));
    struct rte_mbuf *out = (void *)(uintptr_t)1;
    struct foreign_call foreign = {.skb = skb}; pthread_t thread;
    CHECK(pthread_create(&thread, NULL, foreign_worker_call, &foreign) == 0);
    CHECK(pthread_join(thread, NULL) == 0 && foreign.error == -EXDEV);
    uint16_t saved_start = skb->csum_start;
    skb->csum_start = 0;
    CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 2, &out) == -EINVAL && out == (void *)(uintptr_t)1);
    skb->csum_start = saved_start;
    CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 0, &out) == -EINVAL && out == (void *)(uintptr_t)1);
    CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, UINT16_MAX + 1U, &out) == -EOVERFLOW && out == (void *)(uintptr_t)1);
    skb->csum_offset = UINT16_MAX;
    CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 2, &out) == -EINVAL && out == (void *)(uintptr_t)1);
    skb->csum_offset = 2;
    skb->len++;
    CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 2, &out) == -EINVAL && out == (void *)(uintptr_t)1);
    skb->len--;
    CHECK(!memcmp(skb->data, before, sizeof(before)));
    skb_shinfo(skb)->gso_size = 1;
    CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 2, &out) == -ENOTSUP && out == (void *)(uintptr_t)1);
    skb_shinfo(skb)->gso_size = 0;
    skb->nohdr = 1;
    CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 2, &out) == -ENOTSUP && out == (void *)(uintptr_t)1);
    skb->nohdr = 0;
#if defined(CONFIG_IP_SCTP) || defined(CONFIG_IP_SCTP_MODULE)
    skb->csum_not_inet = 1;
    CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 2, &out) == -ENOTSUP && out == (void *)(uintptr_t)1);
    skb->csum_not_inet = 0;
#endif
    unsigned int original_users = refcount_read(&skb->users);
    CHECK(ker_skb_get(skb) == 0);
    CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 2, &out) == -ENOTSUP && out == (void *)(uintptr_t)1);
    CHECK(refcount_read(&skb->users) == original_users + 1 && ker_skb_free(skb) == 0);
    struct ker_skb_queue queue = {0};
    CHECK(ker_skb_queue_init(&queue, &context, 1, SIZE_MAX) == 0);
    struct sk_buff *alias = skb, *popped = NULL;
    CHECK(ker_skb_queue_push(&queue, &skb) == 0 && !skb);
    CHECK(ker_skb_to_mbuf_chain_software_checksum(alias, 2, &out) == -EBUSY && out == (void *)(uintptr_t)1);
    CHECK(ker_skb_queue_pop(&queue, &popped) == 1 && popped == alias);
    CHECK(ker_skb_queue_cleanup(&queue) == 0);
    skb = popped;
    struct rte_mbuf *held[POOL_COUNT]; unsigned int held_count = 0;
    while (held_count < POOL_COUNT && (held[held_count] = ker_packet_alloc(&pool)) != NULL) held_count++;
    CHECK(held_count > 12);
    const unsigned int released[] = {0, 5, 11};
    for (unsigned int trial = 0; trial < 3; trial++) {
        unsigned int count = released[trial];
        while (count--) ker_packet_free(held[--held_count]);
        CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 8, &out) == -ENOMEM);
        CHECK(out == (void *)(uintptr_t)1 && !memcmp(skb->data, before, sizeof(before)));
        CHECK(skb->ip_summed == CHECKSUM_PARTIAL && context.live == 1);
        while ((held[held_count] = ker_packet_alloc(&pool)) != NULL) held_count++;
    }
    while (held_count) ker_packet_free(held[--held_count]);
    CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 2, &out) == 0);
    CHECK(out->nb_segs > 1 && out->pkt_len == sizeof(before));
    CHECK(!memcmp(skb->data, before, sizeof(before)));
    uint8_t flattened[96]; size_t offset = 0;
    for (struct rte_mbuf *seg = out; seg; seg = seg->next) {
        memcpy(flattened + offset, rte_pktmbuf_mtod(seg, const void *), seg->data_len);
        offset += seg->data_len;
    }
    CHECK(offset == sizeof(flattened));
    __sum16 checksum = csum_fold(csum_partial(skb->data + 1, skb->len - 1, 0));
    CHECK(!checksum);
    if (!checksum) checksum = CSUM_MANGLED_0;
    CHECK(!memcmp(flattened + 3, &checksum, sizeof(checksum)));
    CHECK(ker_skb_free(skb) == 0);
    ker_packet_free(out);
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == POOL_COUNT);

    skb = NULL;
    CHECK(ker_skb_alloc(&context, 32, 64, &skb) == 0);
    CHECK(ker_skb_put(skb, 32, &data) == 0);
    memset(data, 0x5a, 32);
    skb->ip_summed = CHECKSUM_PARTIAL;
    skb->csum_start = (uint16_t)skb_headroom(skb);
    skb->csum_offset = 3;
    uint8_t reverse_before[32]; memcpy(reverse_before, skb->data, sizeof(reverse_before));
    CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 8, &out) == 0);
    ker_packet_free(out);
    CHECK(!memcmp(skb->data, reverse_before, sizeof(reverse_before)));
    CHECK(ker_skb_free(skb) == 0 && context.live == 0);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "chain_csum", POOL_COUNT, 0, 4096, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "chain_csum_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "chain_csum0", 10, source_mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device, receive_packet, &receiver) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .rx_budget = 1};
    struct ker_worker_ops ops = {.rx = rx_poll};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);
    rollback_and_synthetic();
    actual_udp_tcp_roundtrip();
    tx_chain_checksum_retry();
    tx_chain_tcp_checksum_cancel();
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_transport_receiver_unregister(&receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == POOL_COUNT);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    return 0;
}
