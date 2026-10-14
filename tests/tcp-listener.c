#include "check.h"
#include "eal.h"
#include "runtime/arp.h"
#include "runtime/arp-responder.h"
#include "runtime/memory.h"
#include "runtime/tcp-listener.h"
#include "runtime/tcp-create.h"
#include "runtime/tcp-neighbor-create.h"
#include "runtime/tx-ring.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static struct ker_neighbor_table neighbors;
static struct ker_receive_runtime runtime;
static struct ker_transport_receiver receiver;
static struct ker_tx_export tx;
static struct ker_tx_ring output;
static struct ker_arp_responder arp;
static struct ker_tcp_listener listener;
static struct ker_tcp_request requests[1];
static struct ker_tcp_listener_config config;
static __be32 local_ip, peer_ip;
static __be16 local_port, peer_port;
static const unsigned char local_mac[6] = {2, 0x10, 0, 0, 0, 1};
static const unsigned char peer_mac[6] = {2, 0x20, 0, 0, 0, 1};
static int tap = -1, isn_error;
static bool reenter;
static int receive_message(const struct ker_transport_message *m, void *arg)
{ (void)m; (void)arg; return NET_RX_DROP; }
static int next_isn(void *arg, __be16 port, uint32_t *out)
{
    (void)arg; CHECK(port);
    if (reenter) {
        struct ker_tcp_request_handle h;
        CHECK(ker_tcp_listener_accept(&listener, &h) == -EBUSY);
        CHECK(ker_tcp_listener_cleanup(&listener) == -EBUSY);
        CHECK(ker_tcp_listener_poll(&listener, listener.now_ms, 1) == -EBUSY);
    }
    if (isn_error) return isn_error;
    if (tap < 0) *out = UINT32_MAX; /* Deterministic tests only. */
    else {
        ssize_t n = getrandom(out, sizeof(*out), GRND_NONBLOCK);
        if (n < 0) return -errno;
        if (n != sizeof(*out)) return -EIO;
    }
    return 0;
}
static int sink(struct rte_mbuf *m, void *arg)
{
    (void)arg;
    if (tap < 0) return ker_tx_ring_sink(m, &output);
    unsigned char bytes[2048];
    if (m->pkt_len > sizeof(bytes)) return -EMSGSIZE;
    const void *data = rte_pktmbuf_read(m, 0, m->pkt_len, bytes);
    if (!data) return -EIO;
    ssize_t n = write(tap, data, m->pkt_len);
    if (n < 0) return -errno;
    if ((size_t)n != m->pkt_len) return -EIO;
    ker_packet_free(m);
    return 0;
}
static void dispatch(struct rte_mbuf *frame)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive(&device, frame, &skb) == 0);
    struct ker_receive_result result = {0};
    int error = ker_receive_dispatch(&runtime, &device, &skb, &result);
    CHECK((error == 0 || (error == -EPROTO && isn_error > 0)) && !skb);
}
static void inject(uint32_t seq, uint32_t ack, uint8_t flags, const void *payload, unsigned int length)
{
    const unsigned char mss[4] = {2, 4, 0x03, 0xe8};
    struct sk_buff *skb = NULL;
    CHECK(ker_tcp_ipv4_create_options(&context, peer_mac, local_mac, peer_ip, local_ip,
        peer_port, local_port, rte_cpu_to_be_32(seq), rte_cpu_to_be_32(ack),
        rte_cpu_to_be_16(1024), flags, 64, flags & KER_TCP_SYN ? mss : NULL,
        flags & KER_TCP_SYN ? sizeof(mss) : 0, payload, length, &skb) == 0);
    struct rte_mbuf *frame = ker_packet_alloc(&pool);
    CHECK(frame);
    void *data = rte_pktmbuf_append(frame, skb->len);
    CHECK(data); memcpy(data, skb->data, skb->len);
    CHECK(ker_skb_free(skb) == 0);
    dispatch(frame);
}
static void fill_tx(void)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_tcp_ipv4_create_neighbor(&neighbors, peer_ip, local_port, peer_port,
        rte_cpu_to_be_32(UINT32_MAX), 0, rte_cpu_to_be_16(1024),
        KER_TCP_SYN | KER_TCP_ACK, 64, NULL, 0, NULL, 0, &skb) == 0);
    CHECK(ker_tx_export_enqueue(&tx, &skb) == 0 && !skb);
}
static uint32_t be32(const unsigned char *p)
{ return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static void drain(uint8_t flags)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == flags);
    CHECK(be32(tcp + 4) == (flags & KER_TCP_SYN ? UINT32_MAX : 0));
    CHECK(be32(tcp + 8) == 0); /* peer SYN at UINT32_MAX */
    ker_packet_free(frame);
}
static uint64_t now_ms(void)
{
    struct timespec t; CHECK(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void test_host(void)
{
    uint64_t deadline = now_ms() + 10000, reset_at = 0;
    struct ker_tcp_request_handle handle;
    bool accepted = false, reset = false;
    while (true) {
        uint64_t now = now_ms(); CHECK(now < deadline);
        CHECK(ker_tcp_listener_poll(&listener, now, 1) >= 0);
        int sent = ker_tx_export_poll(&tx, 8); CHECK(sent >= 0 || sent == -EAGAIN);
        unsigned char bytes[2048];
        ssize_t n = read(tap, bytes, sizeof(bytes));
        if (n < 0) CHECK(errno == EAGAIN || errno == EINTR);
        if (n > 0) {
            struct rte_mbuf *m = ker_packet_alloc(&pool); CHECK(m);
            void *data = rte_pktmbuf_append(m, (uint16_t)n); CHECK(data);
            memcpy(data, bytes, (size_t)n); dispatch(m);
        }
        if (!accepted && ker_tcp_listener_accept(&listener, &handle) == 1) {
            struct ker_tcp_request snapshot;
            CHECK(ker_tcp_listener_snapshot(&listener, handle, &snapshot) == 0);
            CHECK(snapshot.state == KER_TCP_REQUEST_READY && snapshot.send_mss > 0);
            accepted = true; reset_at = now + 100;
        }
        if (accepted && !reset && now >= reset_at) {
            CHECK(ker_tcp_listener_reset(&listener, handle) == 0); reset = true;
        }
        if (reset && !listener.count) break;
        struct pollfd p = {.fd = tap, .events = POLLIN};
        CHECK(poll(&p, 1, 1) >= 0 || errno == EINTR);
    }
    CHECK(arp.replies_enqueued > 0);
}
static void test_listener(void)
{
    struct ker_tcp_request_handle handle = {0}, sentinel = {.slot = 9, .generation = 77};
    CHECK(ker_transport_receiver_unregister(&receiver) == -EBUSY);
    CHECK(ker_tx_export_cleanup(&tx) == -EBUSY);
    CHECK(ker_neighbor_remove(&neighbors, peer_ip) == -EBUSY);
    CHECK(ker_tcp_listener_accept(&listener, &handle) == 0 && !handle.listener);
    const unsigned char syn_data = 1;
    inject(UINT32_MAX, 0, KER_TCP_SYN, &syn_data, 1);
    CHECK(receiver.validation_error == -EOPNOTSUPP && !listener.count && !tx.packets);
    reenter = true;
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0); reenter = false;
    CHECK(listener.count == 1 && requests[0].state == KER_TCP_REQUEST_SYN);
    CHECK(requests[0].send_mss == 1000);
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0);
    CHECK(tx.packets == 1); /* Duplicate SYN does not amplify TX. */
    drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(1, 0, KER_TCP_ACK, NULL, 0); /* wrong sequence */
    inject(0, 1, KER_TCP_ACK, NULL, 0); /* wrong acknowledgment */
    inject(1, 0, KER_TCP_RST, NULL, 0); /* wrong reset sequence */
    CHECK(ker_tcp_listener_accept(&listener, &handle) == 0);
    CHECK(ker_tcp_listener_poll(&listener, 110, 1) == 1);
    drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_accept(&listener, &handle) == 1);
    CHECK(ker_tcp_listener_accept(&listener, &sentinel) == 0 && !sentinel.listener &&
          sentinel.slot == 9 && sentinel.generation == 77);
    CHECK(ker_tcp_listener_poll(&listener, 109, 1) == -EINVAL);
    CHECK(ker_tcp_listener_cleanup(&listener) == -EBUSY);
    const unsigned char payload = 7;
    inject(0, 0, KER_TCP_ACK | KER_TCP_PSH, &payload, 1);
    CHECK(requests[0].state == KER_TCP_REQUEST_RESET && requests[0].error == -EOPNOTSUPP &&
          receiver.validation_error == -EOPNOTSUPP);
    drain(KER_TCP_RST | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, 111, 1) == 1 && !listener.count);
    struct ker_tcp_request snapshot = {.error = 42};
    CHECK(ker_tcp_listener_snapshot(&listener, handle, &snapshot) == -ESTALE && snapshot.error == 42);

    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0);
    drain(KER_TCP_SYN | KER_TCP_ACK);
    __be16 saved_port = peer_port; peer_port = rte_cpu_to_be_16(8001);
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0); peer_port = saved_port;
    CHECK(listener.dropped_full == 1 && tx.packets == 0);
    CHECK(ker_tcp_listener_poll(&listener, 141, 1) == 1 && !listener.count && listener.timed_out == 1);
    isn_error = 1;
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0);
    CHECK(receiver.validation_error == -EPROTO && !listener.count && !tx.packets);
    isn_error = 0;
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0); drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(0, 0, KER_TCP_RST, NULL, 0);
    CHECK(ker_tcp_listener_poll(&listener, 142, 1) == 1 && !listener.count);
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, 172, 0) == 0);
    inject(0, 0, KER_TCP_ACK, NULL, 0);
    CHECK(requests[0].state == KER_TCP_REQUEST_FAILED && listener.timed_out == 2);
    CHECK(ker_tcp_listener_poll(&listener, 173, 1) == 1 && !listener.count);
    fill_tx(); fill_tx();
    uint64_t generation = listener.next_generation;
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0);
    CHECK(receiver.validation_error == -ENOSPC && !listener.count &&
          listener.next_generation == generation);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0);
    fill_tx();
    CHECK(ker_tcp_listener_poll(&listener, 183, 1) == 1 && listener.last_tx_error == -ENOSPC);
    CHECK(ker_tcp_listener_poll(&listener, 203, 1) == 1 && listener.timed_out == 3);
    CHECK(listener.count == 1); /* Queued TX prevents premature record reuse. */
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, 204, 1) == 1 && !listener.count);
    listener.next_generation = UINT64_MAX;
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0);
    CHECK(receiver.validation_error == -EOVERFLOW && !listener.count);
}
int main(int argc, char **argv)
{
    CHECK(argc == 1 || argc == 2);
    if (argc == 2) {
        char *end; errno = 0; long fd = strtol(argv[1], &end, 10);
        CHECK(!errno && end != argv[1] && !*end && fd >= 0 && fd <= INT_MAX);
        tap = (int)fd; CHECK(fcntl(tap, F_SETFL, O_NONBLOCK) == 0);
    }
    local_ip = rte_cpu_to_be_32(0xc0000201); peer_ip = rte_cpu_to_be_32(0xc0000202);
    local_port = rte_cpu_to_be_16(9000); peer_port = rte_cpu_to_be_16(8000);
    ker_test_eal_init(); CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "tcp_listen", 127, 0, 4096, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "tcp_listen_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "tcp_listen0", 32, local_mac) == 0);
    CHECK(ker_arp_device_setup(&device) == 0);
    CHECK(ker_ipv4_address_init(&address, &device, local_ip, 24) == 0);
    CHECK(ker_neighbor_table_init(&neighbors, &address, "tcp_listen_neigh", 4, 2) == 0);
    CHECK(ker_neighbor_add(&neighbors, peer_ip, peer_mac) == 0);
    CHECK(ker_tx_ring_init(&output, "tcp_listen_out", 1, SOCKET_ID_ANY) == 0);
    CHECK(ker_tx_export_init(&tx, &context, 2, 16384, sink, NULL) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device, receive_message, NULL) == 0);
    config = (struct ker_tcp_listener_config){.port = local_port, .window = 1024,
        .mss = 1460, .ttl = 64, .retry_ms = tap < 0 ? 10 : 100,
        .timeout_ms = tap < 0 ? 30 : 3000, .next_isn = next_isn};
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        requests, 1, &config, tap < 0 ? 100 : now_ms()) == 0);
    CHECK(ker_arp_responder_register(&arp, &runtime, &address, &tx) == 0);
    if (tap < 0) test_listener(); else test_host();
    CHECK(ker_tcp_listener_cleanup(&listener) == 0);
    CHECK(ker_arp_responder_unregister(&arp) == 0);
    CHECK(ker_transport_receiver_unregister(&receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_tx_export_cleanup(&tx) == 0);
    CHECK(ker_tx_ring_cleanup(&output) == 0);
    CHECK(ker_neighbor_remove(&neighbors, peer_ip) == 0);
    CHECK(ker_neighbor_table_cleanup(&neighbors) == 0);
    CHECK(ker_ipv4_address_cleanup(&address) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 127);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("bounded TCP passive handshake passed");
    return 0;
}
