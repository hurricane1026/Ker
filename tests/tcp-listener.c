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
static struct ker_tcp_request stream_requests[2];
static unsigned char stream_storage[16];
static unsigned char stream_send_storage[16];
static unsigned char stream_reorder_storage[2];
static unsigned char host_storage[1024];
static unsigned char host_send_storage[1024];
static unsigned char host_reorder_storage[128];
static struct ker_tcp_listener_config config;
static __be32 local_ip, peer_ip;
static __be16 local_port, peer_port;
static const unsigned char local_mac[6] = {2, 0x10, 0, 0, 0, 1};
static const unsigned char peer_mac[6] = {2, 0x20, 0, 0, 0, 1};
static int tap = -1, isn_error;
static bool reenter;
static bool reenter_close;
static struct ker_tcp_request_handle reenter_handle;
static bool host_server_first, host_persist_mode;
static bool host_reorder_mode, host_reorder_held, host_reorder_exercised;
static bool host_persist_zero_seen, host_persist_probe_sent, host_persist_reopen_dropped,
    host_persist_recovered;
static uint32_t host_persist_probe_sequence, host_persist_reopen_ack;
static uint16_t host_persist_reopen_window, host_persist_recovery_window;
static unsigned char host_held_frame[2048];
static size_t host_held_length;
static uint32_t host_held_sequence;
static uint16_t host_held_payload_length;
static bool custom_isn;
static uint32_t custom_isn_value;
static uint16_t peer_mss = 1000;
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
        if (reenter_close) {
            CHECK(ker_tcp_listener_shutdown_write(&listener, reenter_handle) == -EBUSY);
            CHECK(ker_tcp_listener_release(&listener, reenter_handle) == -EBUSY);
        }
    }
    if (isn_error) return isn_error;
    if (tap < 0) *out = custom_isn ? custom_isn_value : UINT32_MAX; /* Deterministic tests only. */
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
    CHECK((error == 0 || error == -ENOSPC || (error == -EPROTO && isn_error > 0)) && !skb);
}
static void inject_window(uint32_t seq, uint32_t ack, uint16_t window, uint8_t flags,
                          const void *payload, unsigned int length)
{
    unsigned char mss[4] = {2, 4, (unsigned char)(peer_mss >> 8), (unsigned char)peer_mss};
    struct sk_buff *skb = NULL;
    CHECK(ker_tcp_ipv4_create_options(&context, peer_mac, local_mac, peer_ip, local_ip,
        peer_port, local_port, rte_cpu_to_be_32(seq), rte_cpu_to_be_32(ack),
        rte_cpu_to_be_16(window), flags, 64, flags & KER_TCP_SYN ? mss : NULL,
        flags & KER_TCP_SYN ? sizeof(mss) : 0, payload, length, &skb) == 0);
    struct rte_mbuf *frame = ker_packet_alloc(&pool);
    CHECK(frame);
    void *data = rte_pktmbuf_append(frame, skb->len);
    CHECK(data); memcpy(data, skb->data, skb->len);
    CHECK(ker_skb_free(skb) == 0);
    dispatch(frame);
}
static void inject(uint32_t seq, uint32_t ack, uint8_t flags, const void *payload,
                   unsigned int length)
{ inject_window(seq, ack, 1024, flags, payload, length); }
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
static void dispatch_bytes(const unsigned char *bytes, size_t length)
{
    struct rte_mbuf *m = ker_packet_alloc(&pool); CHECK(m);
    void *data = rte_pktmbuf_append(m, (uint16_t)length); CHECK(data);
    memcpy(data, bytes, length); dispatch(m);
}
static bool peer_tcp_payload(const unsigned char *frame, size_t length,
                             uint32_t *sequence, uint16_t *payload_length)
{
    if (length < 54 || frame[12] != 0x08 || frame[13] != 0x00) return false;
    const unsigned char *ip = frame + 14;
    unsigned int ihl = (ip[0] & 15U) * 4U;
    if (ihl < 20 || length < 14 + ihl || ip[9] != 6) return false;
    unsigned int total = ((unsigned int)ip[2] << 8) | ip[3];
    if (total < ihl + 20 || length < 14 + total) return false;
    const unsigned char *tcp = ip + ihl;
    __be16 destination; memcpy(&destination, tcp + 2, sizeof(destination));
    if (destination != local_port) return false;
    unsigned int tcp_length = (tcp[12] >> 4) * 4U;
    if (tcp_length < 20 || total < ihl + tcp_length) return false;
    *sequence = be32(tcp + 4);
    *payload_length = (uint16_t)(total - ihl - tcp_length);
    return *payload_length != 0;
}
static void drain(uint8_t flags)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == flags);
    uint32_t expected_sequence = flags & KER_TCP_SYN ? UINT32_MAX : 0;
    if (!(flags & KER_TCP_SYN) && listener.config.send_storage)
        for (size_t i = 0; i < listener.capacity; ++i)
            if (listener.requests[i].peer_port == peer_port)
                expected_sequence = listener.requests[i].send_next;
    CHECK(be32(tcp + 4) == expected_sequence);
    if (flags & KER_TCP_SYN) CHECK(be32(tcp + 8) == 0); /* peer SYN at UINT32_MAX */
    else if (!listener.config.receive_storage)
        CHECK(be32(tcp + 8) == 0); /* legacy peer SYN at UINT32_MAX */
    ker_packet_free(frame);
}
static void drain_ack(uint32_t acknowledgment, uint16_t window)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == KER_TCP_ACK && be32(tcp + 8) == acknowledgment);
    CHECK((((unsigned int)tcp[14] << 8) | tcp[15]) == window);
    ker_packet_free(frame);
}
static void drain_data(uint32_t sequence, uint32_t acknowledgment, uint16_t window,
                       const void *expected, uint16_t length)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == (KER_TCP_ACK | KER_TCP_PSH) && be32(tcp + 4) == sequence &&
          be32(tcp + 8) == acknowledgment && rte_pktmbuf_pkt_len(frame) >= 54 + length &&
          (((unsigned int)tcp[14] << 8) | tcp[15]) == window &&
          !memcmp(tcp + 20, expected, length));
    ker_packet_free(frame);
}
static void drain_rst_ack(uint32_t acknowledgment)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == (KER_TCP_RST | KER_TCP_ACK));
    CHECK(be32(tcp + 8) == acknowledgment);
    ker_packet_free(frame);
}
static void drain_reset_values(uint32_t sequence, uint32_t acknowledgment)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == (KER_TCP_RST | KER_TCP_ACK) && be32(tcp + 4) == sequence &&
          be32(tcp + 8) == acknowledgment);
    ker_packet_free(frame);
}
static void drain_control_ack(uint8_t flags, uint32_t acknowledgment)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == flags && be32(tcp + 8) == acknowledgment);
    ker_packet_free(frame);
}
static void drain_close(uint8_t flags, uint32_t sequence, uint32_t acknowledgment,
                        uint16_t window)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == flags && be32(tcp + 4) == sequence &&
          be32(tcp + 8) == acknowledgment &&
          (((unsigned int)tcp[14] << 8) | tcp[15]) == window);
    ker_packet_free(frame);
}
static void drain_syn_ack(uint32_t sequence, uint32_t acknowledgment)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == (KER_TCP_SYN | KER_TCP_ACK) && be32(tcp + 4) == sequence &&
          be32(tcp + 8) == acknowledgment);
    ker_packet_free(frame);
}
static uint64_t now_ms(void)
{
    struct timespec t; CHECK(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void test_host(void)
{
    const size_t request_goal = 4096;
    const size_t response_goal = host_persist_mode ? 65536 : 4096;
    uint64_t deadline = now_ms() + 10000;
    struct ker_tcp_request_handle handle;
    bool accepted = false, shutdown = false, closed = false, peer_eof = false;
    size_t received = 0, sent = 0;
    while (true) {
        uint64_t now = now_ms(); CHECK(now < deadline);
        CHECK(ker_tcp_listener_poll(&listener, now, 1) >= 0);
        int exported = ker_tx_export_poll(&tx, 8); CHECK(exported >= 0 || exported == -EAGAIN);
        unsigned char bytes[2048];
        ssize_t n = read(tap, bytes, sizeof(bytes));
        if (n < 0) CHECK(errno == EAGAIN || errno == EINTR);
        if (n > 0) {
            bool drop_frame = false, dispatch_done = false;
            if (host_persist_mode && accepted &&
                n >= 54 && bytes[12] == 8 && bytes[13] == 0 && bytes[23] == 6 &&
                bytes[26] == 192 && bytes[27] == 0 && bytes[28] == 2 && bytes[29] == 2 &&
                bytes[30] == 192 && bytes[31] == 0 && bytes[32] == 2 && bytes[33] == 1) {
                size_t ihl = (size_t)(bytes[14] & 15) * 4, tcp = 14 + ihl;
                size_t ip_length = ((size_t)bytes[16] << 8) | bytes[17];
                if ((bytes[14] >> 4) == 4 && bytes[23] == 6 && ihl >= 20 &&
                    ip_length >= ihl + 20 && ip_length <= (size_t)n - 14 &&
                    tcp + 20 <= 14 + ip_length && bytes[tcp] == 0x1f && bytes[tcp + 1] == 0x43 &&
                    bytes[tcp + 2] == 0x23 && bytes[tcp + 3] == 0x28 &&
                    (bytes[tcp + 12] >> 4) >= 5 &&
                    tcp + (((size_t)bytes[tcp + 12] >> 4) * 4) <= 14 + ip_length) {
                    struct ker_tcp_request *r = &listener.requests[handle.slot];
                    uint32_t sequence = be32(bytes + tcp + 4);
                    uint32_t acknowledgment = be32(bytes + tcp + 8);
                    uint16_t window = ((uint16_t)bytes[tcp + 14] << 8) | bytes[tcp + 15];
                    if (!host_persist_reopen_dropped && r->send_bytes == 1 &&
                        r->peer_window == 0 && host_persist_probe_sent &&
                        r->send_right == host_persist_probe_sequence &&
                        r->send_next == host_persist_probe_sequence + 1U &&
                        sequence == r->receive_next && bytes[tcp + 13] == KER_TCP_ACK && window &&
                        acknowledgment == host_persist_probe_sequence) {
                        host_persist_reopen_ack = acknowledgment;
                        host_persist_reopen_window = window;
                        host_persist_reopen_dropped = true;
                        drop_frame = true;
                    }
                    if (!drop_frame && host_persist_reopen_dropped && !host_persist_recovered &&
                        r->send_bytes == 1 && r->peer_window == 0 &&
                        sequence == r->receive_next && bytes[tcp + 13] == KER_TCP_ACK && window &&
                        acknowledgment == host_persist_probe_sequence + 1U) {
                        uint32_t recovery_ack = acknowledgment;
                        host_persist_recovery_window = window;
                        dispatch_bytes(bytes, (size_t)n);
                        CHECK(!r->send_bytes && r->send_unacknowledged == recovery_ack &&
                            r->peer_window == host_persist_recovery_window &&
                            r->send_right == recovery_ack + host_persist_recovery_window);
                        host_persist_recovered = true;
                        if (!r->peer_window && r->send_right == r->send_next)
                            host_persist_zero_seen = true;
                        dispatch_done = true;
                    }
                }
            }
            if (!drop_frame && !dispatch_done) {
                uint32_t sequence = 0;
                uint16_t payload_length = 0;
                if (host_reorder_mode && !host_reorder_exercised &&
                    peer_tcp_payload(bytes, (size_t)n, &sequence, &payload_length)) {
                    if (!host_reorder_held) {
                        CHECK((size_t)n <= sizeof(host_held_frame));
                        memcpy(host_held_frame, bytes, (size_t)n);
                        host_held_length = (size_t)n;
                        host_held_sequence = sequence;
                        host_held_payload_length = payload_length;
                        host_reorder_held = true;
                        continue;
                    }
                    if (sequence == host_held_sequence + host_held_payload_length) {
                        /* Deliver a later sequence first, prove it is retained but not ACKed through. */
                        dispatch_bytes(bytes, (size_t)n);
                        CHECK(listener.requests[0].receive_next == host_held_sequence &&
                              memcmp(host_reorder_storage, (unsigned char[128]){0},
                                     sizeof(host_reorder_storage)) != 0);
                        dispatch_bytes(host_held_frame, host_held_length);
                        CHECK(listener.requests[0].receive_next == sequence + payload_length &&
                              memcmp(host_reorder_storage, (unsigned char[128]){0},
                                     sizeof(host_reorder_storage)) == 0);
                        host_reorder_exercised = true;
                        continue;
                    }
                }
                dispatch_bytes(bytes, (size_t)n);
                if (host_persist_mode && accepted &&
                    !listener.requests[handle.slot].peer_window &&
                    listener.requests[handle.slot].send_right ==
                        listener.requests[handle.slot].send_next)
                    host_persist_zero_seen = true;
            }
        }
        if (!accepted && ker_tcp_listener_accept(&listener, &handle) == 1) {
            struct ker_tcp_request snapshot;
            CHECK(ker_tcp_listener_snapshot(&listener, handle, &snapshot) == 0);
            CHECK(snapshot.state == KER_TCP_REQUEST_READY && snapshot.send_mss > 0);
            accepted = true;
        }
        if (accepted && !shutdown) {
            unsigned char payload[512];
            int n = ker_tcp_listener_read(&listener, handle, payload, sizeof(payload));
            if (n > 0) {
                for (int i = 0; i < n; ++i)
                    CHECK(payload[i] == (unsigned char)((received + (size_t)i) & 0xff));
                received += (size_t)n;
            } else if (n == 0) peer_eof = true;
            else CHECK(n == -EAGAIN);
            if (!listener.requests[handle.slot].send_bytes && sent < response_goal) {
                unsigned char payload[1024];
                size_t amount = sizeof(payload);
                if (amount > response_goal - sent) amount = response_goal - sent;
                for (size_t i = 0; i < amount; ++i) payload[i] = (unsigned char)((sent + i + 37) & 0xff);
                int written = ker_tcp_listener_write(&listener, handle, payload, (uint16_t)amount);
                if (written > 0) {
                    if (host_persist_mode && !host_persist_probe_sent &&
                        listener.requests[handle.slot].peer_window == 0 && written == 1) {
                        host_persist_probe_sent = true;
                        host_persist_probe_sequence = listener.requests[handle.slot].send_unacknowledged;
                    }
                    sent += (size_t)written;
                }
                else CHECK(written == -EAGAIN);
            }
        }
        if (accepted && (peer_eof || host_server_first) && !shutdown &&
            received == request_goal && sent == response_goal &&
            !listener.requests[0].send_bytes) {
            if (host_server_first) {
                CHECK(!listener.requests[handle.slot].peer_eof &&
                      listener.requests[handle.slot].state == KER_TCP_REQUEST_READY);
            } else {
                CHECK(listener.requests[handle.slot].peer_eof &&
                      listener.requests[handle.slot].state == KER_TCP_REQUEST_CLOSE_WAIT);
            }
            CHECK(ker_tcp_listener_shutdown_write(&listener, handle) == 0); shutdown = true;
            CHECK(listener.requests[handle.slot].state == (host_server_first ?
                  KER_TCP_REQUEST_FIN_WAIT_1 : KER_TCP_REQUEST_LAST_ACK) &&
                  listener.requests[handle.slot].active_close == host_server_first);
        }
        if (shutdown && listener.requests[handle.slot].state == KER_TCP_REQUEST_CLOSED && !tx.packets) {
            CHECK(listener.requests[handle.slot].peer_eof &&
                  listener.requests[handle.slot].local_fin_acked &&
                  listener.requests[handle.slot].active_close == host_server_first);
            CHECK(ker_tcp_listener_release(&listener, handle) == 0);
            closed = true;
        }
        if (closed && !listener.count) break;
        struct pollfd p = {.fd = tap, .events = POLLIN};
        CHECK(poll(&p, 1, 1) >= 0 || errno == EINTR);
    }
    CHECK(arp.replies_enqueued > 0);
    if (host_reorder_mode) CHECK(host_reorder_exercised);
    if (host_persist_mode && !(host_persist_zero_seen && host_persist_probe_sent &&
        host_persist_reopen_dropped && host_persist_recovered)) {
        fprintf(stderr, "persist proof zero=%d probe=%d dropped=%d recovered=%d seq=%u ack=%u win=%u recwin=%u\n",
            host_persist_zero_seen, host_persist_probe_sent, host_persist_reopen_dropped,
            host_persist_recovered, host_persist_probe_sequence, host_persist_reopen_ack,
            host_persist_reopen_window, host_persist_recovery_window);
        CHECK(false);
    }
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

    /* Without opt-in close, an empty final ACK|FIN remains explicitly unsupported. */
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0); drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    CHECK(requests[0].state == KER_TCP_REQUEST_RESET &&
          requests[0].error == -EOPNOTSUPP && tx.packets == 1);
    drain(KER_TCP_RST | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, 111, 1) == 1 && !listener.count);

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
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0); drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    CHECK(requests[0].state == KER_TCP_REQUEST_RESET && receiver.validation_error == -EOPNOTSUPP);
    CHECK(ker_tcp_listener_accept(&listener, &sentinel) == 0);
    drain(KER_TCP_RST | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, 205, 1) == 1 && !listener.count);
    listener.next_generation = UINT64_MAX;
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0);
    CHECK(receiver.validation_error == -EOVERFLOW && !listener.count);
}
static void test_stream(void)
{
    CHECK(ker_tcp_listener_cleanup(&listener) == 0);
    listener.next_generation = 0; /* Isolated test fixture after overflow case. */
    memset(stream_requests, 0, sizeof(stream_requests));
    memset(stream_storage, 0, sizeof(stream_storage));
    memset(stream_send_storage, 0, sizeof(stream_send_storage));
    config.receive_storage = stream_storage;
    config.receive_storage_size = sizeof(stream_storage);
    config.receive_capacity = 8;
    config.window = 16; /* SYN-ACK must clamp to the actual per-slot ring. */
    config.receive_storage_size--;
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, 300) == -EINVAL && !tx.listener_refs);
    config.receive_storage_size++;
    config.send_storage = stream_send_storage;
    config.send_storage_size = sizeof(stream_send_storage);
    config.send_capacity = 8;
    config.send_storage_size--;
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, 300) == -EINVAL && !tx.listener_refs);
    config.send_storage_size++;
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, 300) == 0);

    peer_port = rte_cpu_to_be_16(8000);
    inject(UINT32_MAX - 3, 0, KER_TCP_SYN, NULL, 0);
    CHECK(tx.packets == 1 && listener.count == 1);
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == (KER_TCP_SYN | KER_TCP_ACK));
    CHECK((((unsigned int)tcp[14] << 8) | tcp[15]) == 8);
    CHECK(be32(tcp + 8) == UINT32_MAX - 2);
    ker_packet_free(frame);

    /* The final ACK carries data across the 32-bit receive-sequence wrap. */
    inject(UINT32_MAX - 2, 0, KER_TCP_ACK | KER_TCP_PSH, "abcdef", 6);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_READY &&
          stream_requests[0].receive_next == 3 && stream_requests[0].receive_bytes == 6);
    drain_ack(3, 2);
    struct ker_tcp_request_handle first, second, other;
    char out[16] = {0};
    struct ker_tcp_request_handle unaccepted = {&listener, 0, stream_requests[0].generation};
    CHECK(ker_tcp_listener_read(&listener, unaccepted, out, sizeof(out)) == -EPERM);
    CHECK(ker_tcp_listener_accept(&listener, &first) == 1);
    CHECK(ker_tcp_listener_read(&listener, first, out, 4) == 4 && !memcmp(out, "abcd", 4));
    CHECK(ker_tcp_listener_poll(&listener, 301, 2) == 2);
    drain_ack(3, 6);
    /* Tail wraps the physical ring while the admitted edge remains bounded. */
    inject(3, 0, KER_TCP_ACK | KER_TCP_PSH, "ghijkl", 6);
    CHECK(stream_requests[0].receive_next == 9 && stream_requests[0].receive_bytes == 8);
    drain_ack(9, 0);
    inject(10, 0, KER_TCP_ACK | KER_TCP_PSH, "z", 1); /* future gap */
    CHECK(stream_requests[0].receive_next == 9 && stream_requests[0].receive_bytes == 8);
    drain_ack(9, 0);
    inject(7, 0, KER_TCP_ACK | KER_TCP_PSH, "klXX", 4); /* duplicate overlap, full */
    CHECK(stream_requests[0].receive_next == 9 && stream_requests[0].receive_bytes == 8);
    drain_ack(9, 0);
    memset(out, 0, sizeof(out));
    CHECK(ker_tcp_listener_read(&listener, first, out, sizeof(out)) == 8 &&
          !memcmp(out, "efghijkl", 8));
    /* A read cannot reopen the edge until its window ACK is admitted. */
    fill_tx(); fill_tx();
    inject(9, 0, KER_TCP_ACK | KER_TCP_PSH, "M", 1);
    CHECK(stream_requests[0].receive_next == 9 && stream_requests[0].receive_bytes == 0 &&
          stream_requests[0].receive_right == 9);
    CHECK(ker_tcp_listener_poll(&listener, 303, 2) == 2 && listener.last_tx_error == -ENOSPC);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, 304, 2) == 2);
    drain_ack(9, 8);
    /* ACK failure preserves newly accepted bytes for a later retry. */
    fill_tx(); fill_tx();
    inject(9, 0, KER_TCP_ACK | KER_TCP_PSH, "M", 1);
    CHECK(stream_requests[0].receive_next == 10 && stream_requests[0].receive_bytes == 1 &&
          stream_requests[0].receive_right == 17);
    CHECK(ker_tcp_listener_poll(&listener, 305, 2) == 2 && listener.last_tx_error == -ENOSPC);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, 306, 2) == 2);
    drain_ack(10, 7);
    CHECK(ker_tcp_listener_read(&listener, first, out, sizeof(out)) == 1 && out[0] == 'M');
    CHECK(ker_tcp_listener_poll(&listener, 307, 2) == 2);
    drain_ack(10, 8);

    /* A second accepted slot has independent sequence and storage. */
    peer_port = rte_cpu_to_be_16(8001);
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0);
    drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_accept(&listener, &second) == 1);
    CHECK(stream_requests[1].send_unacknowledged == 0 && stream_requests[1].send_next == 0 &&
          stream_requests[1].peer_window == 1024);
    inject(0, 0, KER_TCP_ACK | KER_TCP_PSH, "Q", 1);
    CHECK(stream_requests[0].receive_bytes == 0 && stream_requests[1].receive_bytes == 1);
    drain_ack(1, 7);
    memset(out, 0, sizeof(out));
    CHECK(ker_tcp_listener_read(&listener, second, out, sizeof(out)) == 1 && out[0] == 'Q');
    /* Admission is transactional; a full exporter leaves sequence and ring untouched. */
    fill_tx(); fill_tx();
    uint32_t old_right = stream_requests[1].receive_right;
    CHECK(stream_requests[1].ack_pending);
    CHECK(ker_tcp_listener_write(&listener, second, "123456789", 9) == -ENOSPC &&
          stream_requests[1].send_next == 0 && stream_requests[1].send_bytes == 0 &&
          stream_requests[1].ack_pending && stream_requests[1].receive_right == old_right);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    char outgoing[] = "abcdefghijk";
    CHECK(ker_tcp_listener_write(&listener, second, outgoing, sizeof(outgoing) - 1) == 8);
    CHECK(!stream_requests[1].ack_pending && stream_requests[1].receive_right == 9);
    CHECK(!stream_requests[0].send_bytes &&
          !memcmp(stream_send_storage + 8, "abcdefgh", 8) &&
          !memcmp(stream_send_storage, "\0\0\0\0\0\0\0\0", 8));
    memcpy(outgoing, "XXXXXXXXXXX", sizeof(outgoing));
    drain_data(0, 1, 8, "abcdefgh", 8);
    CHECK(stream_requests[1].send_next == 8 && stream_requests[1].send_bytes == 8);
    uint32_t saved_right = stream_requests[1].send_right;
    uint16_t saved_window = stream_requests[1].peer_window;
    inject_window(0, 3, 0, KER_TCP_ACK, NULL, 0); /* stale sequence cannot ACK send data */
    inject_window(2, 3, 0, KER_TCP_ACK, NULL, 0); /* future sequence cannot ACK either */
    CHECK(stream_requests[1].send_unacknowledged == 0 && stream_requests[1].send_bytes == 8 &&
          stream_requests[1].peer_window == saved_window &&
          stream_requests[1].send_right == saved_right);
    inject(2, 3, KER_TCP_ACK | KER_TCP_PSH, "G", 1); /* receive gap is not ACK-eligible */
    drain_ack(1, 8);
    inject(0, 3, KER_TCP_ACK | KER_TCP_PSH, "Z", 1); /* wholly old duplicate */
    drain_ack(1, 8);
    CHECK(stream_requests[1].send_unacknowledged == 0 && stream_requests[1].send_bytes == 8 &&
          stream_requests[1].peer_window == saved_window &&
          stream_requests[1].send_right == saved_right);
    /* Partial ACK advances UNA and retransmits only the preserved suffix. */
    inject(0, 3, KER_TCP_ACK | KER_TCP_PSH, "XR", 2); /* valid overlap reaches receive_next */
    CHECK(stream_requests[1].send_unacknowledged == 3 && stream_requests[1].send_bytes == 5 &&
          stream_requests[1].receive_next == 2 && stream_requests[1].receive_bytes == 1);
    drain_ack(2, 7);
    CHECK(ker_tcp_listener_poll(&listener, 318, 2) == 2);
    drain_data(3, 2, 7, "defgh", 5);
    inject_window(2, 8, 0, KER_TCP_ACK, NULL, 0);
    CHECK(stream_requests[1].send_unacknowledged == 8 && !stream_requests[1].send_bytes);
    CHECK(ker_tcp_listener_write(&listener, second, "01234567", 8) == -EAGAIN);
    /* A future gap cannot reopen the exhausted peer window. */
    inject_window(3, 8, 3, KER_TCP_ACK | KER_TCP_PSH, "G", 1);
    drain_ack(2, 7);
    CHECK(stream_requests[1].send_right == 8 && stream_requests[1].peer_window == 0 &&
          ker_tcp_listener_write(&listener, second, "01234567", 8) == -EAGAIN);
    /* A valid overlap carries one new byte and may reopen that send window. */
    inject_window(1, 8, 3, KER_TCP_ACK | KER_TCP_PSH, "RS", 2);
    CHECK(stream_requests[1].receive_next == 3 && stream_requests[1].receive_bytes == 2 &&
          stream_requests[1].send_unacknowledged == 8 && !stream_requests[1].send_bytes &&
          stream_requests[1].peer_window == 3 && stream_requests[1].send_right == 11);
    drain_ack(3, 6);
    CHECK(ker_tcp_listener_write(&listener, second, "01234567", 8) == 3);
    drain_data(8, 3, 6, "012", 3);
    inject(3, 11, KER_TCP_ACK, NULL, 0);
    CHECK(stream_requests[1].send_unacknowledged == 11 && !stream_requests[1].send_bytes);
    inject(3, 12, KER_TCP_ACK, NULL, 0); /* future ACK cannot advance state */
    CHECK(stream_requests[1].send_unacknowledged == 11 && !stream_requests[1].send_bytes);
    CHECK(ker_tcp_listener_read(&listener, second, out, sizeof(out)) == 2 &&
          !memcmp(out, "RS", 2));
    peer_port = rte_cpu_to_be_16(8000);
    inject(10, 0, KER_TCP_ACK | KER_TCP_PSH, "U", 1);
    CHECK(stream_requests[0].receive_bytes == 1);
    drain_ack(11, 7);
    CHECK(ker_tcp_listener_reset(&listener, first) == 0);
    CHECK(stream_requests[0].receive_bytes == 0 && !stream_requests[0].ack_pending);
    drain(KER_TCP_RST | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, 319, 2) == 2);
    drain_ack(3, 8);
    peer_port = rte_cpu_to_be_16(8001);
    inject(3, 11, KER_TCP_ACK | KER_TCP_PSH | KER_TCP_FIN, "X", 1);
    CHECK(stream_requests[1].state == KER_TCP_REQUEST_RESET &&
          stream_requests[1].error == -EOPNOTSUPP && stream_requests[1].receive_bytes == 0);
    drain(KER_TCP_RST | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, 320, 2) == 2 && !listener.count);

    /* An unacknowledged copy retries with backoff, then expires at its fixed deadline. */
    peer_port = rte_cpu_to_be_16(8005);
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0); drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_accept(&listener, &second) == 1);
    CHECK(ker_tcp_listener_write(&listener, second, "timeout", 7) == 7);
    drain_data(0, 0, 8, "timeout", 7);
    uint64_t fixed_deadline = stream_requests[0].send_deadline_ms;
    CHECK(stream_requests[0].send_retry_ms == 330 && fixed_deadline == 350);
    CHECK(ker_tcp_listener_poll(&listener, 330, 2) == 2);
    drain_data(0, 0, 8, "timeout", 7);
    CHECK(stream_requests[0].send_retry_ms == 350 &&
          stream_requests[0].send_deadline_ms == fixed_deadline);

    /* A separate slot accepts a valid ACK before its own deadline. */
    peer_port = rte_cpu_to_be_16(8006);
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0); drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_accept(&listener, &other) == 1);
    CHECK(ker_tcp_listener_write(&listener, other, "ok", 2) == 2);
    drain_data(0, 0, 8, "ok", 2);
    inject(0, 2, KER_TCP_ACK, NULL, 0);
    CHECK(stream_requests[1].state == KER_TCP_REQUEST_READY &&
          stream_requests[1].send_unacknowledged == 2 && !stream_requests[1].send_bytes);

    /* Budgeted polling refreshes now but skips slot zero at its deadline. */
    listener.cursor = 1;
    CHECK(ker_tcp_listener_poll(&listener, 350, 1) == 1 &&
          stream_requests[0].state == KER_TCP_REQUEST_READY && stream_requests[0].send_bytes == 7 &&
          stream_requests[1].state == KER_TCP_REQUEST_READY);
    peer_port = rte_cpu_to_be_16(8005);
    inject(0, 7, KER_TCP_ACK | KER_TCP_PSH, "L", 1);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_FAILED &&
          stream_requests[0].error == -ETIMEDOUT && !stream_requests[0].send_bytes &&
          stream_requests[0].send_unacknowledged == 0 && stream_requests[0].peer_window == 1024 &&
          stream_requests[0].send_right == 1024 && stream_requests[0].receive_next == 0 &&
          stream_requests[0].receive_bytes == 0);
    CHECK(stream_requests[1].state == KER_TCP_REQUEST_READY &&
          stream_requests[1].send_unacknowledged == 2 && !stream_requests[1].send_bytes);
    CHECK(ker_tcp_listener_reset(&listener, second) == 0);
    drain_reset_values(7, 0);
    CHECK(ker_tcp_listener_poll(&listener, 351, 2) == 2 && listener.count == 1);
    peer_port = rte_cpu_to_be_16(8006);
    CHECK(ker_tcp_listener_reset(&listener, other) == 0);
    drain_reset_values(2, 0);
    CHECK(ker_tcp_listener_poll(&listener, 352, 2) == 2 && !listener.count);

    /* Unsupported payload flags and RST matching use progressed stream seq. */
    peer_port = rte_cpu_to_be_16(8002);
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0); drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_accept(&listener, &second) == 1);
    inject(0, 0, KER_TCP_ACK | KER_TCP_PSH, "Q", 1); drain_ack(1, 7);
    inject(1, 0, KER_TCP_ACK | KER_TCP_ECE, "X", 1);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_RESET &&
          stream_requests[0].error == -EOPNOTSUPP && stream_requests[0].receive_bytes == 0);
    drain(KER_TCP_RST | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, 352, 2) == 2 && !listener.count);

    peer_port = rte_cpu_to_be_16(8003);
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0); drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_accept(&listener, &second) == 1);
    inject(0, 0, KER_TCP_ACK | KER_TCP_PSH, "Q", 1); drain_ack(1, 7);
    inject(0, 0, KER_TCP_RST, NULL, 0); /* stale sequence cannot abort stream */
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_READY && stream_requests[0].receive_bytes == 1);
    inject(1, 0, KER_TCP_RST, NULL, 0); /* exact progressed receive sequence */
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_FAILED &&
          stream_requests[0].error == -ECONNRESET && stream_requests[0].receive_bytes == 0 &&
          stream_requests[0].receive_next == 1 && !stream_requests[0].ack_pending);
    struct ker_tcp_request failed;
    CHECK(ker_tcp_listener_snapshot(&listener, second, &failed) == 0 &&
          failed.receive_next == 1 && !failed.receive_bytes);
    memset(out, 0xa5, sizeof(out));
    CHECK(ker_tcp_listener_read(&listener, second, out, sizeof(out)) == -ECONNRESET &&
          (unsigned char)out[0] == 0xa5);
    CHECK(ker_tcp_listener_reset(&listener, second) == 0);
    drain_rst_ack(1);
    CHECK(ker_tcp_listener_poll(&listener, 353, 2) == 2 && !listener.count);

    /* A failed pre-handshake stream slot also keeps its initial peer sequence. */
    peer_port = rte_cpu_to_be_16(8004);
    const uint32_t peer_isn = 0x12345678;
    inject(peer_isn, 0, KER_TCP_SYN, NULL, 0);
    inject(peer_isn + 1, 0, KER_TCP_RST, NULL, 0);
    size_t failed_slot = 0;
    while (failed_slot < listener.capacity &&
           stream_requests[failed_slot].peer_port != peer_port) ++failed_slot;
    CHECK(failed_slot < listener.capacity &&
          stream_requests[failed_slot].state == KER_TCP_REQUEST_FAILED &&
          stream_requests[failed_slot].receive_next == peer_isn + 1);
    struct ker_tcp_request_handle failed_syn = {&listener, failed_slot,
        stream_requests[failed_slot].generation};
    CHECK(ker_tcp_listener_reset(&listener, failed_syn) == 0);
    drain_control_ack(KER_TCP_SYN | KER_TCP_ACK, peer_isn + 1);
    drain_rst_ack(peer_isn + 1);
    CHECK(ker_tcp_listener_poll(&listener, 354, 2) == 2 && !listener.count);
    /* Send-only storage still preserves both sequence spaces on pre-handshake reset. */
    CHECK(ker_tcp_listener_cleanup(&listener) == 0);
    config.receive_storage = NULL;
    config.receive_storage_size = 0;
    config.receive_capacity = 0;
    config.window = 1024;
    custom_isn = true; custom_isn_value = 0x10203040;
    peer_port = rte_cpu_to_be_16(8006);
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, 355) == 0);
    const uint32_t send_only_peer_isn = 0x55667788;
    inject(send_only_peer_isn, 0, KER_TCP_SYN, NULL, 0);
    drain_syn_ack(custom_isn_value, send_only_peer_isn + 1);
    inject(send_only_peer_isn + 1, 0, KER_TCP_RST, NULL, 0);
    size_t send_only_slot = 0;
    while (send_only_slot < listener.capacity &&
           stream_requests[send_only_slot].peer_port != peer_port) ++send_only_slot;
    CHECK(send_only_slot < listener.capacity &&
          stream_requests[send_only_slot].receive_next == send_only_peer_isn + 1 &&
          stream_requests[send_only_slot].send_next == custom_isn_value + 1);
    struct ker_tcp_request_handle send_only_failed = {&listener, send_only_slot,
        stream_requests[send_only_slot].generation};
    CHECK(ker_tcp_listener_reset(&listener, send_only_failed) == 0);
    drain_reset_values(custom_isn_value + 1, send_only_peer_isn + 1);
    CHECK(ker_tcp_listener_poll(&listener, 356, 2) == 2 && !listener.count);
    CHECK(ker_tcp_listener_cleanup(&listener) == 0);
    /* A payload flight crosses UINT32_MAX; partial ACK retries only its suffix. */
    custom_isn_value = UINT32_MAX - 2;
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, 357) == 0);
    peer_port = rte_cpu_to_be_16(8007);
    peer_mss = 3;
    inject(send_only_peer_isn, 0, KER_TCP_SYN, NULL, 0);
    peer_mss = 1000;
    drain_syn_ack(custom_isn_value, send_only_peer_isn + 1);
    inject(send_only_peer_isn + 1, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_accept(&listener, &second) == 1);
    CHECK(stream_requests[0].send_mss == 3);
    CHECK(ker_tcp_listener_write(&listener, second, "wrap", 4) == 3);
    drain_data(UINT32_MAX - 1, send_only_peer_isn + 1, 1024, "wra", 3);
    inject(send_only_peer_isn + 1, 0, KER_TCP_ACK, NULL, 0);
    CHECK(stream_requests[0].send_unacknowledged == 0 && stream_requests[0].send_bytes == 1);
    CHECK(ker_tcp_listener_poll(&listener, 367, 2) == 2);
    drain_data(0, send_only_peer_isn + 1, 1024, "a", 1);
    inject(send_only_peer_isn + 1, 1, KER_TCP_ACK, NULL, 0);
    CHECK(stream_requests[0].send_unacknowledged == 1 && !stream_requests[0].send_bytes);
    CHECK(ker_tcp_listener_reset(&listener, second) == 0);
    drain_reset_values(1, send_only_peer_isn + 1);
    CHECK(ker_tcp_listener_poll(&listener, 368, 2) == 2 && !listener.count);
    CHECK(ker_tcp_listener_cleanup(&listener) == 0);

    /* Poll still expires an unacknowledged send at its absolute deadline. */
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, 368) == 0);
    peer_port = rte_cpu_to_be_16(8008);
    inject(UINT32_MAX, 0, KER_TCP_SYN, NULL, 0);
    drain_syn_ack(custom_isn_value, 0);
    inject(0, custom_isn_value + 1U, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_accept(&listener, &second) == 1);
    CHECK(ker_tcp_listener_write(&listener, second, "x", 1) == 1);
    drain_data(custom_isn_value + 1U, 0, 1024, "x", 1);
    uint64_t poll_deadline = stream_requests[0].send_deadline_ms;
    listener.cursor = 0;
    CHECK(ker_tcp_listener_poll(&listener, poll_deadline, 1) == 1 &&
          stream_requests[0].state == KER_TCP_REQUEST_FAILED &&
          stream_requests[0].error == -ETIMEDOUT && !stream_requests[0].send_bytes);
    CHECK(ker_tcp_listener_reset(&listener, second) == 0);
    drain_reset_values(custom_isn_value + 2U, 0);
    CHECK(ker_tcp_listener_poll(&listener, poll_deadline + 1, 2) == 2 && !listener.count);

    /* Opt-in passive zero-window recovery admits one real byte transactionally. */
    CHECK(ker_tcp_listener_cleanup(&listener) == 0);
    config.receive_storage = stream_storage;
    config.receive_storage_size = sizeof(stream_storage);
    config.receive_capacity = 8;
    config.window = 8;
    config.zero_window_probe = false;
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, poll_deadline + 1) == 0);
    peer_port = rte_cpu_to_be_16(8009);
    custom_isn = true; custom_isn_value = UINT32_MAX - 1U;
    memset(stream_send_storage, 0xcc, sizeof(stream_send_storage));
    inject(50, 0, KER_TCP_SYN, NULL, 0);
    drain_syn_ack(custom_isn_value, 51);
    inject(51, custom_isn_value + 1U, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle persist_peer;
    CHECK(ker_tcp_listener_accept(&listener, &persist_peer) == 1);
    inject_window(51, UINT32_MAX, 0, KER_TCP_ACK, NULL, 0);
    CHECK(stream_requests[persist_peer.slot].peer_window == 0 &&
          stream_requests[persist_peer.slot].send_right == UINT32_MAX &&
          stream_requests[persist_peer.slot].send_next == UINT32_MAX);
    unsigned char probe_source[] = {0xa5, 0xb6, 0xc7};
    CHECK(ker_tcp_listener_write(&listener, persist_peer, probe_source,
        sizeof(probe_source)) == -EAGAIN); /* Legacy default remains closed. */
    stream_requests[persist_peer.slot].send_right = UINT32_MAX - 1U;
    listener.config.zero_window_probe = true;
    CHECK(ker_tcp_listener_write(&listener, persist_peer, probe_source,
        sizeof(probe_source)) == -EAGAIN); /* Serial-negative edge is not zero. */
    stream_requests[persist_peer.slot].send_right = UINT32_MAX;
    fill_tx(); fill_tx();
    uint32_t old_next = stream_requests[persist_peer.slot].send_next;
    uint32_t old_una = stream_requests[persist_peer.slot].send_unacknowledged;
    uint32_t persist_old_right = stream_requests[persist_peer.slot].send_right;
    memset(stream_send_storage, 0xcc, sizeof(stream_send_storage));
    CHECK(ker_tcp_listener_write(&listener, persist_peer, probe_source,
        sizeof(probe_source)) == -ENOSPC);
    CHECK(stream_requests[persist_peer.slot].send_next == old_next &&
          stream_requests[persist_peer.slot].send_unacknowledged == old_una &&
          stream_requests[persist_peer.slot].send_right == persist_old_right &&
          !stream_requests[persist_peer.slot].send_bytes &&
          !stream_requests[persist_peer.slot].send_retry_ms &&
          !stream_requests[persist_peer.slot].send_deadline_ms &&
          stream_send_storage[0] == 0xcc && stream_send_storage[8] == 0xcc &&
          probe_source[0] == 0xa5);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_listener_write(&listener, persist_peer, probe_source,
        sizeof(probe_source)) == 1);
    CHECK(stream_requests[persist_peer.slot].send_bytes == 1 &&
          stream_requests[persist_peer.slot].send_next == 0 &&
          stream_send_storage[0] == 0xa5 && stream_send_storage[8] == 0xcc);
    drain_data(UINT32_MAX, 51, 8, probe_source, 1);
    uint64_t slot_a_deadline = stream_requests[persist_peer.slot].send_deadline_ms;
    uint64_t slot_a_retry = stream_requests[persist_peer.slot].send_retry_ms;
    uint64_t slot_a_backoff = stream_requests[persist_peer.slot].send_backoff_ms;
    /* A second slot sends and retires independently while slot A probes. */
    peer_port = rte_cpu_to_be_16(8010);
    inject(100, 0, KER_TCP_SYN, NULL, 0);
    drain_syn_ack(custom_isn_value, 101);
    inject(101, custom_isn_value + 1U, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_accept(&listener, &other) == 1 && other.slot != persist_peer.slot);
    inject_window(101, UINT32_MAX, 4, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_write(&listener, other, "B", 1) == 1 &&
          !memcmp(stream_send_storage + other.slot * 8, "B", 1));
    CHECK(stream_requests[persist_peer.slot].send_bytes == 1 &&
          stream_requests[persist_peer.slot].send_unacknowledged == UINT32_MAX &&
          stream_requests[persist_peer.slot].send_next == 0 &&
          stream_requests[persist_peer.slot].send_right == UINT32_MAX &&
          stream_requests[persist_peer.slot].peer_window == 0 &&
          stream_requests[persist_peer.slot].send_deadline_ms == slot_a_deadline &&
          stream_requests[persist_peer.slot].send_retry_ms == slot_a_retry &&
          stream_requests[persist_peer.slot].send_backoff_ms == slot_a_backoff);
    drain_data(UINT32_MAX, 101, 8, "B", 1);
    inject_window(101, 0, 4, KER_TCP_ACK, NULL, 0);
    CHECK(!stream_requests[other.slot].send_bytes &&
          stream_requests[persist_peer.slot].send_bytes == 1 &&
          stream_requests[persist_peer.slot].send_deadline_ms == slot_a_deadline &&
          stream_requests[persist_peer.slot].send_retry_ms == slot_a_retry &&
          stream_requests[persist_peer.slot].send_backoff_ms == slot_a_backoff &&
          stream_send_storage[0] == 0xa5 && stream_send_storage[8] == 'B');
    CHECK(ker_tcp_listener_reset(&listener, other) == 0);
    drain_reset_values(0, 101);
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms + 1, 2) == 2);
    peer_port = rte_cpu_to_be_16(8009);
    uint64_t persist_deadline = stream_requests[persist_peer.slot].send_deadline_ms;
    uint64_t persist_retry = stream_requests[persist_peer.slot].send_retry_ms;
    uint64_t persist_backoff = stream_requests[persist_peer.slot].send_backoff_ms;
    inject_window(51, UINT32_MAX, 0, KER_TCP_ACK, NULL, 0);
    CHECK(stream_requests[persist_peer.slot].send_bytes == 1 &&
          stream_requests[persist_peer.slot].send_next == 0 &&
          stream_requests[persist_peer.slot].send_deadline_ms == persist_deadline &&
          stream_requests[persist_peer.slot].send_retry_ms == persist_retry &&
          stream_requests[persist_peer.slot].send_backoff_ms == persist_backoff);
    inject_window(51, UINT32_MAX, 2, KER_TCP_ACK, NULL, 0);
    CHECK(stream_requests[persist_peer.slot].send_bytes == 1 &&
          stream_requests[persist_peer.slot].peer_window == 2 &&
          stream_requests[persist_peer.slot].send_right == 1 &&
          stream_requests[persist_peer.slot].send_deadline_ms == persist_deadline &&
          stream_requests[persist_peer.slot].send_retry_ms == persist_retry &&
          stream_requests[persist_peer.slot].send_backoff_ms == persist_backoff);
    inject_window(50, 0, 4, KER_TCP_ACK, NULL, 0); /* Stale receive sequence. */
    inject_window(51, 1, 4, KER_TCP_ACK, NULL, 0); /* Future send ACK. */
    CHECK(stream_requests[persist_peer.slot].send_bytes == 1 &&
          stream_requests[persist_peer.slot].send_unacknowledged == UINT32_MAX &&
          stream_requests[persist_peer.slot].send_right == 1 &&
          stream_requests[persist_peer.slot].send_deadline_ms == persist_deadline);
    CHECK(ker_tcp_listener_poll(&listener, persist_retry, 2) == 2);
    drain_data(UINT32_MAX, 51, 8, probe_source, 1);
    CHECK(stream_requests[persist_peer.slot].send_deadline_ms == persist_deadline &&
          stream_requests[persist_peer.slot].send_backoff_ms == 20);
    inject_window(51, 0, 2, KER_TCP_ACK, NULL, 0); /* ACK==NXT after wrap. */
    CHECK(!stream_requests[persist_peer.slot].send_bytes &&
          stream_requests[persist_peer.slot].send_unacknowledged == 0 &&
          !stream_requests[persist_peer.slot].send_deadline_ms &&
          !stream_requests[persist_peer.slot].send_retry_ms &&
          !stream_requests[persist_peer.slot].send_backoff_ms);
    CHECK(ker_tcp_listener_reset(&listener, persist_peer) == 0);
    drain_reset_values(0, 51);
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms + 1, 2) == 2 && !listener.count);

    /* A budget-skipped probe expires in RX before a valid late ACK can mutate it. */
    peer_port = rte_cpu_to_be_16(8011);
    inject(70, 0, KER_TCP_SYN, NULL, 0);
    drain_syn_ack(custom_isn_value, 71);
    inject(71, custom_isn_value + 1U, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_accept(&listener, &persist_peer) == 1);
    inject_window(71, UINT32_MAX, 0, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_write(&listener, persist_peer, "Z", 1) == 1);
    drain_data(UINT32_MAX, 71, 8, "Z", 1);
    fill_tx(); fill_tx();
    inject_window(71, UINT32_MAX, 0, KER_TCP_ACK | KER_TCP_PSH, "R", 1);
    CHECK(stream_requests[persist_peer.slot].receive_bytes == 1 &&
          stream_requests[persist_peer.slot].receive_next == 72 &&
          stream_requests[persist_peer.slot].ack_pending && stream_storage[0] == 'R');
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    peer_port = rte_cpu_to_be_16(8012);
    inject(110, 0, KER_TCP_SYN, NULL, 0);
    drain_syn_ack(custom_isn_value, 111);
    inject(111, custom_isn_value + 1U, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_listener_accept(&listener, &other) == 1 && other.slot != persist_peer.slot);
    struct ker_tcp_request *expiring = &stream_requests[persist_peer.slot];
    uint64_t deadline = expiring->send_deadline_ms;
    uint32_t saved_next = expiring->send_next, saved_una = expiring->send_unacknowledged;
    uint32_t saved_send_right = expiring->send_right, saved_receive_right = expiring->receive_right;
    uint16_t expired_peer_window = expiring->peer_window;
    uint8_t saved_head = expiring->receive_head;
    listener.cursor = other.slot;
    unsigned int inspected_deadline = ker_tcp_listener_poll(&listener, deadline, 1);
    CHECK(inspected_deadline == 1 && expiring->state == KER_TCP_REQUEST_READY &&
          stream_requests[other.slot].state == KER_TCP_REQUEST_READY);
    peer_port = rte_cpu_to_be_16(8011);
    inject_window(72, 0, 4, KER_TCP_ACK, NULL, 0);
    CHECK(expiring->state == KER_TCP_REQUEST_FAILED && expiring->error == -ETIMEDOUT &&
          !expiring->send_bytes && expiring->send_next == saved_next &&
          expiring->send_unacknowledged == saved_una && expiring->send_right == saved_send_right &&
          expiring->peer_window == expired_peer_window && expiring->receive_bytes == 1 &&
          expiring->receive_head == saved_head && expiring->receive_next == 72 &&
          expiring->receive_right == saved_receive_right && expiring->ack_pending &&
          stream_requests[other.slot].state == KER_TCP_REQUEST_READY);
    CHECK(ker_tcp_listener_reset(&listener, persist_peer) == 0);
    drain_reset_values(0, 72);
    CHECK(ker_tcp_listener_reset(&listener, other) == 0);
    drain_reset_values(custom_isn_value + 1U, 111);
    CHECK(ker_tcp_listener_poll(&listener, deadline + 1, 2) == 2 && !listener.count);
    listener.config.zero_window_probe = false;
    CHECK(ker_tcp_listener_cleanup(&listener) == 0);
    custom_isn = false;
    config.receive_storage = NULL;
    config.receive_storage_size = 0;
    config.receive_capacity = 0;
    config.send_storage = NULL;
    config.send_storage_size = 0;
    config.send_capacity = 0;
    peer_port = rte_cpu_to_be_16(8000);
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        requests, 1, &config, 357) == 0);
}
static void test_passive_close(void)
{
    CHECK(ker_tcp_listener_cleanup(&listener) == 0);
    memset(stream_requests, 0, sizeof(stream_requests));
    memset(stream_storage, 0, sizeof(stream_storage));
    memset(stream_send_storage, 0, sizeof(stream_send_storage));
    config.receive_storage = stream_storage;
    config.receive_storage_size = sizeof(stream_storage);
    config.receive_capacity = 8;
    config.send_storage = stream_send_storage;
    config.send_storage_size = sizeof(stream_send_storage);
    config.send_capacity = 8;
    config.window = 8;
    config.time_wait_ms = 50;
    config.reorder_storage = stream_reorder_storage;
    config.reorder_storage_size = 1;
    custom_isn = true; custom_isn_value = 0x10203040;
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, 390) == -EINVAL);
    config.reorder_storage_size = sizeof(stream_reorder_storage);
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, 400) == 0);

    /* Send timeout removes only OOO metadata; the pre-existing RX ring survives. */
    peer_port = rte_cpu_to_be_16(8023);
    inject(900, 0, KER_TCP_SYN, NULL, 0);
    drain_syn_ack(custom_isn_value, 901);
    inject(901, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle timeout_peer;
    CHECK(ker_tcp_listener_accept(&listener, &timeout_peer) == 1);
    inject(901, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "a", 1);
    drain_ack(902, 7);
    peer_port = rte_cpu_to_be_16(8020);
    fill_tx(); fill_tx();
    peer_port = rte_cpu_to_be_16(8023);
    inject(903, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH | KER_TCP_FIN, "c", 1);
    CHECK(listener.last_tx_error == -ENOSPC && stream_requests[0].ack_pending);
    peer_port = rte_cpu_to_be_16(8020);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    peer_port = rte_cpu_to_be_16(8023);
    CHECK(stream_requests[0].receive_bytes == 1 && stream_reorder_storage[0] &&
          stream_requests[0].reorder_fin_pending);
    CHECK(ker_tcp_listener_write(&listener, timeout_peer, "timeout", 7) == 7);
    drain_data(custom_isn_value + 1, 902, 7, "timeout", 7);
    struct ker_tcp_request timeout_before = stream_requests[0];
    CHECK(ker_tcp_listener_poll(&listener, timeout_before.send_deadline_ms, 2) == 2);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_FAILED &&
          stream_requests[0].receive_next == timeout_before.receive_next &&
          stream_requests[0].receive_right == timeout_before.receive_right &&
          stream_requests[0].receive_head == timeout_before.receive_head &&
          stream_requests[0].receive_bytes == timeout_before.receive_bytes &&
          stream_requests[0].ack_pending == timeout_before.ack_pending &&
          !stream_reorder_storage[0] && !stream_requests[0].reorder_fin_pending);
    CHECK(ker_tcp_listener_reset(&listener, timeout_peer) == 0);
    drain_reset_values(custom_isn_value + 8, 902);
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms + 1, 2) == 2 && !listener.count);

    /* Bitmap-backed OOO bytes survive wrap, overlaps, full ring and ACK backpressure. */
    peer_port = rte_cpu_to_be_16(8021);
    inject(UINT32_MAX - 2U, 0, KER_TCP_SYN, NULL, 0);
    drain_syn_ack(custom_isn_value, UINT32_MAX - 1U);
    inject(UINT32_MAX - 1U, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle reorder_peer;
    CHECK(ker_tcp_listener_accept(&listener, &reorder_peer) == 1 && reorder_peer.slot == 0);
    inject(UINT32_MAX - 1U, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "ab", 2);
    drain_ack(0, 6);
    peer_port = rte_cpu_to_be_16(8020);
    fill_tx(); fill_tx();
    peer_port = rte_cpu_to_be_16(8021);
    inject(2, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "ef", 2);
    CHECK(stream_requests[0].receive_next == 0 && stream_requests[0].receive_bytes == 2 &&
          (stream_reorder_storage[0] & 0x30) == 0x30 && stream_requests[0].ack_pending &&
          listener.last_tx_error == -ENOSPC);
    peer_port = rte_cpu_to_be_16(8020);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    peer_port = rte_cpu_to_be_16(8021);
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms, 2) == 2);
    drain_ack(0, 6);
    inject(2, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "XY", 2);
    drain_ack(0, 6); /* First-retained bytes win a conflicting duplicate. */
    inject(UINT32_MAX, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "bcd", 3);
    CHECK(stream_requests[0].receive_next == 4 && stream_requests[0].receive_bytes == 6);
    drain_ack(4, 2);
    CHECK(stream_requests[0].receive_next == 4 && stream_requests[0].receive_bytes == 6 &&
          !stream_reorder_storage[0]);
    char reorder_bytes[8] = {0};
    CHECK(ker_tcp_listener_read(&listener, reorder_peer, reorder_bytes, 6) == 6 &&
          !memcmp(reorder_bytes, "abcdef", 6));
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms + 1, 2) == 2);
    drain_ack(4, 8);
    inject(11, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "z", 1);
    drain_ack(4, 8);
    inject(4, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "1234567", 7);
    drain_ack(12, 0);
    CHECK(stream_requests[0].receive_bytes == 8 && stream_requests[0].receive_next == 12);
    CHECK(ker_tcp_listener_read(&listener, reorder_peer, reorder_bytes, 1) == 1 &&
          reorder_bytes[0] == '1');
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms + 1, 2) == 2);
    drain_ack(12, 1);
    CHECK(ker_tcp_listener_read(&listener, reorder_peer, reorder_bytes, 7) == 7 &&
          !memcmp(reorder_bytes, "234567z", 7));
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms + 1, 2) == 2);
    drain_ack(12, 8);
    inject(14, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "X", 1);
    CHECK(stream_reorder_storage[0]);
    drain_ack(12, 8);
    CHECK(ker_tcp_listener_reset(&listener, reorder_peer) == 0 && !stream_reorder_storage[0]);
    drain_reset_values(custom_isn_value + 1, 12);
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms + 1, 2) == 2);
    peer_port = rte_cpu_to_be_16(8021);
    inject(20, 0, KER_TCP_SYN, NULL, 0); drain_syn_ack(custom_isn_value, 21);
    inject(21, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle reused_peer;
    CHECK(ker_tcp_listener_accept(&listener, &reused_peer) == 1 && reused_peer.slot == 0 &&
          !stream_reorder_storage[0]);

    /* Out-of-order FIN is held behind its gap and bounds later data. */
    peer_port = rte_cpu_to_be_16(8022);
    inject(500, 0, KER_TCP_SYN, NULL, 0); drain_syn_ack(custom_isn_value, 501);
    inject(501, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle fin_gap_peer;
    CHECK(ker_tcp_listener_accept(&listener, &fin_gap_peer) == 1 && fin_gap_peer.slot == 1);
    inject(503, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH | KER_TCP_FIN, "de", 2);
    drain_ack(501, 8);
    CHECK(stream_requests[1].receive_next == 501 && !stream_requests[1].peer_eof &&
          stream_reorder_storage[1]);
    inject(505, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "X", 1);
    drain_ack(501, 8);
    CHECK(stream_requests[1].receive_next == 501 && stream_requests[1].receive_bytes == 0);
    inject(501, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "bc", 2);
    drain_ack(506, 3);
    CHECK(stream_requests[1].peer_eof && stream_requests[1].receive_next == 506 &&
          stream_requests[1].receive_bytes == 4 && !stream_reorder_storage[1]);
    CHECK(ker_tcp_listener_read(&listener, fin_gap_peer, reorder_bytes, 8) == 4 &&
          !memcmp(reorder_bytes, "bcde", 4));
    CHECK(ker_tcp_listener_read(&listener, fin_gap_peer, reorder_bytes, 8) == 0);
    CHECK(ker_tcp_listener_reset(&listener, reused_peer) == 0);
    drain_reset_values(custom_isn_value + 1, 21);
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms + 1, 2) == 2);
    CHECK(ker_tcp_listener_shutdown_write(&listener, fin_gap_peer) == 0);
    drain_close(KER_TCP_ACK | KER_TCP_FIN, custom_isn_value + 1, 506, 3);
    inject(506, custom_isn_value + 2, KER_TCP_ACK, NULL, 0);
    CHECK(stream_requests[1].state == KER_TCP_REQUEST_CLOSED);
    CHECK(ker_tcp_listener_release(&listener, fin_gap_peer) == 0);
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms + 1, 2) == 2 && !listener.count);
    CHECK(ker_tcp_listener_cleanup(&listener) == 0);
    memset(stream_requests, 0, sizeof(stream_requests));
    memset(stream_storage, 0, sizeof(stream_storage));
    memset(stream_send_storage, 0, sizeof(stream_send_storage));
    memset(stream_reorder_storage, 0, sizeof(stream_reorder_storage));
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, 400) == 0);
    peer_port = rte_cpu_to_be_16(8010);
    inject(100, 0, KER_TCP_SYN, NULL, 0);
    drain_syn_ack(custom_isn_value, 101);
    inject(101, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle peer_first;
    CHECK(ker_tcp_listener_accept(&listener, &peer_first) == 1);
    inject(101, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "abc", 3);
    drain_ack(104, 5);
    inject(104, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_CLOSE_WAIT &&
          stream_requests[0].peer_eof && stream_requests[0].receive_next == 105);
    drain_ack(105, 4);
    char bytes[8] = {0};
    CHECK(ker_tcp_listener_read(&listener, peer_first, bytes, sizeof(bytes)) == 3 &&
          !memcmp(bytes, "abc", 3));
    CHECK(ker_tcp_listener_read(&listener, peer_first, bytes, sizeof(bytes)) == 0);
    reenter_handle = peer_first;
    reenter = reenter_close = true;
    peer_port = rte_cpu_to_be_16(8013);
    inject(400, 0, KER_TCP_SYN, NULL, 0);
    reenter = reenter_close = false;
    drain_syn_ack(custom_isn_value, 401);
    inject(401, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle reentry_peer;
    CHECK(ker_tcp_listener_accept(&listener, &reentry_peer) == 1);
    CHECK(ker_tcp_listener_reset(&listener, reentry_peer) == 0);
    drain(KER_TCP_RST | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, 402, 2) == 2);
    peer_port = rte_cpu_to_be_16(8010);
    CHECK(ker_tcp_listener_write(&listener, peer_first, "z", 1) == 1);
    drain_data(custom_isn_value + 1, 105, 4, "z", 1);
    uint32_t saved_send_right = stream_requests[0].send_right;
    uint16_t saved_peer_window = stream_requests[0].peer_window;
    inject(105, custom_isn_value + 2, KER_TCP_ACK | KER_TCP_PSH, "Q", 1);
    drain_ack(105, 4);
    CHECK(stream_requests[0].send_unacknowledged == custom_isn_value + 1 &&
          stream_requests[0].send_bytes == 1 && stream_requests[0].send_right == saved_send_right &&
          stream_requests[0].peer_window == saved_peer_window);
    inject(103, custom_isn_value + 2, KER_TCP_ACK | KER_TCP_PSH | KER_TCP_FIN, "x", 1);
    drain_ack(105, 4);
    CHECK(stream_requests[0].send_unacknowledged == custom_isn_value + 1 &&
          stream_requests[0].send_bytes == 1 && stream_requests[0].send_right == saved_send_right &&
          stream_requests[0].peer_window == saved_peer_window);
    inject(104, custom_isn_value + 2, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    drain_ack(105, 4);
    inject(105, custom_isn_value + 2, KER_TCP_ACK, NULL, 0);
    CHECK(!stream_requests[0].send_bytes);
    CHECK(ker_tcp_listener_shutdown_write(&listener, peer_first) == 0 &&
          stream_requests[0].state == KER_TCP_REQUEST_LAST_ACK);
    drain_close(KER_TCP_ACK | KER_TCP_FIN, custom_isn_value + 2, 105, 4);
    inject(104, custom_isn_value + 3, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    drain_ack(105, 4);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_CLOSED &&
          stream_requests[0].local_fin_acked);
    CHECK(ker_tcp_listener_release(&listener, peer_first) == 0);

    /* The final handshake ACK may carry the first payload and FIN. */
    peer_port = rte_cpu_to_be_16(8012);
    inject(300, 0, KER_TCP_SYN, NULL, 0);
    drain_syn_ack(custom_isn_value, 301);
    inject(301, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH | KER_TCP_FIN, "f", 1);
    CHECK(ker_tcp_listener_accept(&listener, &peer_first) == 1 &&
          stream_requests[0].state == KER_TCP_REQUEST_CLOSE_WAIT &&
          stream_requests[0].receive_next == 303);
    drain_ack(303, 6);
    CHECK(ker_tcp_listener_read(&listener, peer_first, bytes, sizeof(bytes)) == 1 && bytes[0] == 'f');
    CHECK(ker_tcp_listener_read(&listener, peer_first, bytes, sizeof(bytes)) == 0);
    CHECK(ker_tcp_listener_shutdown_write(&listener, peer_first) == 0);
    drain_close(KER_TCP_ACK | KER_TCP_FIN, custom_isn_value + 1, 303, 6);
    inject(303, custom_isn_value + 2, KER_TCP_ACK, NULL, 0);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_CLOSED);
    CHECK(ker_tcp_listener_release(&listener, peer_first) == 0);

    /* A zero-payload final ACK|FIN consumes FIN and defers its ACK under pressure. */
    peer_port = rte_cpu_to_be_16(8020);
    inject(700, 0, KER_TCP_SYN, NULL, 0); drain_syn_ack(custom_isn_value, 701);
    fill_tx(); fill_tx();
    inject(701, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    struct ker_tcp_request_handle empty_fin;
    CHECK(ker_tcp_listener_accept(&listener, &empty_fin) == 1 &&
          stream_requests[0].state == KER_TCP_REQUEST_CLOSE_WAIT &&
          stream_requests[0].peer_eof && stream_requests[0].receive_next == 702 &&
          !stream_requests[0].receive_bytes && stream_requests[0].ack_pending);
    CHECK(ker_tcp_listener_read(&listener, empty_fin, bytes, sizeof(bytes)) == 0);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms, 2) == 2 &&
          !stream_requests[0].ack_pending);
    drain_ack(702, 7);
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms + 10, 2) == 2 && !tx.packets);
    CHECK(ker_tcp_listener_reset(&listener, empty_fin) == 0);
    drain_reset_values(custom_isn_value + 1, 702);
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms + 11, 2) == 2 &&
          !listener.count);

    peer_port = rte_cpu_to_be_16(8011);
    inject(200, 0, KER_TCP_SYN, NULL, 0);
    drain_syn_ack(custom_isn_value, 201);
    inject(201, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle server_first;
    CHECK(ker_tcp_listener_accept(&listener, &server_first) == 1);
    fill_tx(); fill_tx();
    uint32_t before_fin = stream_requests[0].send_next;
    CHECK(ker_tcp_listener_shutdown_write(&listener, server_first) == -ENOSPC &&
          stream_requests[0].state == KER_TCP_REQUEST_READY &&
          !stream_requests[0].local_fin && stream_requests[0].send_next == before_fin);
    drain(KER_TCP_SYN | KER_TCP_ACK);
    drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(201, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "12345678", 8);
    drain_ack(209, 0);
    CHECK(ker_tcp_listener_shutdown_write(&listener, server_first) == 0 &&
          stream_requests[0].state == KER_TCP_REQUEST_FIN_WAIT_1);
    drain_close(KER_TCP_ACK | KER_TCP_FIN, custom_isn_value + 1, 209, 0);
    CHECK(ker_tcp_listener_read(&listener, server_first, bytes, 1) == 1 && bytes[0] == '1');
    CHECK(ker_tcp_listener_poll(&listener, listener.now_ms + 1, 2) == 2);
    drain_ack(209, 1);
    inject(209, custom_isn_value + 2, KER_TCP_ACK, NULL, 0);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_FIN_WAIT_2);
    inject(209, custom_isn_value + 2, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_TIME_WAIT &&
          stream_requests[0].peer_eof && stream_requests[0].local_fin_acked);
    CHECK(ker_tcp_listener_reset(&listener, server_first) == -EBUSY);
    uint64_t fixed_tw = stream_requests[0].time_wait_deadline_ms;
    drain_ack(210, 0);
    inject(209, 0, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    drain_ack(210, 0);
    inject(210, custom_isn_value + 2, KER_TCP_RST, NULL, 0);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_TIME_WAIT &&
          stream_requests[0].time_wait_deadline_ms == fixed_tw);
    CHECK(ker_tcp_listener_read(&listener, server_first, bytes, 1) == 1 && bytes[0] == '2' &&
          !stream_requests[0].ack_pending &&
          stream_requests[0].receive_next == 210 && stream_requests[0].receive_right == 210 &&
          !tx.packets);
    CHECK(ker_tcp_listener_poll(&listener, fixed_tw, 2) == 2 &&
          stream_requests[0].state == KER_TCP_REQUEST_CLOSED);
    inject(209, 0, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    inject(210, custom_isn_value + 2, KER_TCP_RST, NULL, 0);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_CLOSED && !tx.packets);
    CHECK(ker_tcp_listener_read(&listener, server_first, bytes, sizeof(bytes)) == 6 &&
          !memcmp(bytes, "345678", 6) && !stream_requests[0].ack_pending && !tx.packets);
    CHECK(ker_tcp_listener_read(&listener, server_first, bytes, sizeof(bytes)) == 0 && !tx.packets);
    CHECK(ker_tcp_listener_release(&listener, server_first) == 0);

    /* An old prefix ending at the edge may carry the first FIN while ACKing ours. */
    peer_port = rte_cpu_to_be_16(8014);
    inject(500, 0, KER_TCP_SYN, NULL, 0); drain_syn_ack(custom_isn_value, 501);
    inject(501, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle overlap_fin;
    CHECK(ker_tcp_listener_accept(&listener, &overlap_fin) == 1);
    inject(501, custom_isn_value + 1, KER_TCP_ACK | KER_TCP_PSH, "abc", 3);
    drain_ack(504, 5);
    CHECK(ker_tcp_listener_shutdown_write(&listener, overlap_fin) == 0);
    drain_close(KER_TCP_ACK | KER_TCP_FIN, custom_isn_value + 1, 504, 5);
    uint32_t fin_sequence = stream_requests[0].send_next;
    inject(502, fin_sequence, KER_TCP_ACK | KER_TCP_FIN | KER_TCP_PSH, "bc", 2);
    drain_ack(505, 4);
    CHECK(stream_requests[0].peer_eof && stream_requests[0].local_fin_acked &&
          stream_requests[0].receive_next == 505 && stream_requests[0].receive_bytes == 3 &&
          stream_requests[0].send_next == fin_sequence &&
          stream_requests[0].state == KER_TCP_REQUEST_TIME_WAIT);
    CHECK(ker_tcp_listener_read(&listener, overlap_fin, bytes, sizeof(bytes)) == 3 &&
          !memcmp(bytes, "abc", 3));
    CHECK(ker_tcp_listener_poll(&listener, stream_requests[0].time_wait_deadline_ms, 2) == 2 &&
          stream_requests[0].state == KER_TCP_REQUEST_CLOSED);
    CHECK(ker_tcp_listener_release(&listener, overlap_fin) == 0);
    CHECK(ker_tcp_listener_cleanup(&listener) == 0);
    /* FIN retry keeps one sequence/edge and the original close deadline. */
    config.timeout_ms = 60;
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, 600) == 0);
    peer_port = rte_cpu_to_be_16(8015);
    inject(600, 0, KER_TCP_SYN, NULL, 0); drain_syn_ack(custom_isn_value, 601);
    inject(601, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle retry_close;
    CHECK(ker_tcp_listener_accept(&listener, &retry_close) == 1);
    CHECK(ker_tcp_listener_shutdown_write(&listener, retry_close) == 0);
    uint32_t retry_fin_seq = stream_requests[0].send_unacknowledged;
    uint32_t retry_receive_edge = stream_requests[0].receive_right;
    uint64_t retry_close_deadline = stream_requests[0].close_deadline_ms;
    drain_close(KER_TCP_ACK | KER_TCP_FIN, retry_fin_seq, 601, 8);
    fill_tx(); fill_tx();
    CHECK(ker_tcp_listener_poll(&listener, 610, 2) == 2 &&
          listener.last_tx_error == -ENOSPC && stream_requests[0].send_next == retry_fin_seq + 1 &&
          stream_requests[0].send_retry_ms == 630 &&
          stream_requests[0].close_deadline_ms == retry_close_deadline &&
          stream_requests[0].receive_right == retry_receive_edge);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_listener_poll(&listener, 630, 2) == 2);
    drain_close(KER_TCP_ACK | KER_TCP_FIN, retry_fin_seq, 601, 8);
    CHECK(stream_requests[0].send_retry_ms == 670 &&
          stream_requests[0].close_deadline_ms == retry_close_deadline);
    CHECK(ker_tcp_listener_poll(&listener, retry_close_deadline, 2) == 2 &&
          stream_requests[0].state == KER_TCP_REQUEST_FAILED &&
          stream_requests[0].error == -ETIMEDOUT && !tx.packets);
    CHECK(ker_tcp_listener_reset(&listener, retry_close) == 0);
    drain_reset_values(retry_fin_seq + 1, 601);
    CHECK(ker_tcp_listener_poll(&listener, retry_close_deadline + 1, 2) == 2 &&
          !listener.count && ker_tcp_listener_cleanup(&listener) == 0);
    config.timeout_ms = 30;
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, 700) == 0);
    peer_port = rte_cpu_to_be_16(8016);
    inject(700, 0, KER_TCP_SYN, NULL, 0); drain_syn_ack(custom_isn_value, 701);
    inject(701, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle budget_close;
    CHECK(ker_tcp_listener_accept(&listener, &budget_close) == 1);
    peer_port = rte_cpu_to_be_16(8017);
    inject(800, 0, KER_TCP_SYN, NULL, 0); drain_syn_ack(custom_isn_value, 801);
    inject(801, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle budget_other;
    CHECK(ker_tcp_listener_accept(&listener, &budget_other) == 1);
    peer_port = rte_cpu_to_be_16(8016);
    CHECK(ker_tcp_listener_shutdown_write(&listener, budget_close) == 0);
    drain_close(KER_TCP_ACK | KER_TCP_FIN, custom_isn_value + 1, 701, 8);
    uint32_t saved_una = stream_requests[0].send_unacknowledged;
    uint32_t saved_next = stream_requests[0].send_next;
    uint32_t saved_right = stream_requests[0].send_right;
    uint32_t saved_receive = stream_requests[0].receive_next;
    uint16_t saved_window = stream_requests[0].peer_window;
    uint64_t saved_deadline = stream_requests[0].close_deadline_ms;
    listener.cursor = 1;
    CHECK(ker_tcp_listener_poll(&listener, saved_deadline, 1) == 1 &&
          stream_requests[0].state == KER_TCP_REQUEST_FIN_WAIT_1);
    inject(701, saved_next, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_FAILED &&
          stream_requests[0].error == -ETIMEDOUT && !stream_requests[0].peer_eof &&
          !stream_requests[0].local_fin_acked && stream_requests[0].send_unacknowledged == saved_una &&
          stream_requests[0].send_next == saved_next && stream_requests[0].send_right == saved_right &&
          stream_requests[0].peer_window == saved_window &&
          stream_requests[0].receive_next == saved_receive && !stream_requests[0].receive_bytes &&
          !tx.packets);
    CHECK(ker_tcp_listener_reset(&listener, budget_close) == 0);
    drain_reset_values(saved_next, saved_receive);
    CHECK(ker_tcp_listener_reset(&listener, budget_other) == 0);
    drain_reset_values(custom_isn_value + 1, 801);
    CHECK(ker_tcp_listener_poll(&listener, saved_deadline + 1, 2) == 2 &&
          !listener.count && ker_tcp_listener_cleanup(&listener) == 0);
    /* Shutdown overflow is transactional even though the connection is otherwise writable. */
    const uint64_t max_clock = UINT64_MAX;
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, max_clock - 40) == 0);
    peer_port = rte_cpu_to_be_16(8018);
    inject(900, 0, KER_TCP_SYN, NULL, 0); drain_syn_ack(custom_isn_value, 901);
    inject(901, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle overflow_close;
    CHECK(ker_tcp_listener_accept(&listener, &overflow_close) == 1);
    CHECK(ker_tcp_listener_poll(&listener, max_clock - 29, 2) == 2);
    uint32_t overflow_send_next = stream_requests[0].send_next;
    CHECK(ker_tcp_listener_shutdown_write(&listener, overflow_close) == -EOVERFLOW &&
          stream_requests[0].state == KER_TCP_REQUEST_READY && !stream_requests[0].local_fin &&
          stream_requests[0].send_next == overflow_send_next && !tx.packets);
    CHECK(ker_tcp_listener_reset(&listener, overflow_close) == 0);
    drain_reset_values(overflow_send_next, 901);
    CHECK(ker_tcp_listener_poll(&listener, max_clock - 28, 2) == 2 &&
          !listener.count && ker_tcp_listener_cleanup(&listener) == 0);

    /* A saturated TIME_WAIT expiry fails closed and pins the ID until fixture teardown. */
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        stream_requests, 2, &config, max_clock - 100) == 0);
    peer_port = rte_cpu_to_be_16(8019);
    inject(1000, 0, KER_TCP_SYN, NULL, 0); drain_syn_ack(custom_isn_value, 1001);
    inject(1001, custom_isn_value + 1, KER_TCP_ACK, NULL, 0);
    struct ker_tcp_request_handle saturated_close;
    CHECK(ker_tcp_listener_accept(&listener, &saturated_close) == 1);
    CHECK(ker_tcp_listener_poll(&listener, max_clock - 60, 2) == 2);
    CHECK(ker_tcp_listener_shutdown_write(&listener, saturated_close) == 0);
    uint32_t saturated_fin_next = stream_requests[0].send_next;
    drain_close(KER_TCP_ACK | KER_TCP_FIN, saturated_fin_next - 1, 1001, 8);
    CHECK(ker_tcp_listener_poll(&listener, max_clock - 49, 2) == 2);
    drain_close(KER_TCP_ACK | KER_TCP_FIN, saturated_fin_next - 1, 1001, 8);
    inject(1001, saturated_fin_next, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    drain_ack(1002, 7);
    CHECK(stream_requests[0].state == KER_TCP_REQUEST_TIME_WAIT &&
          stream_requests[0].time_wait_saturated &&
          stream_requests[0].time_wait_deadline_ms == UINT64_MAX &&
          ker_tcp_listener_release(&listener, saturated_close) == -EBUSY &&
          ker_tcp_listener_cleanup(&listener) == -EBUSY);
    /* Intentional non-expiring fixture: restore storage directly after asserting fail-closed guards. */
    memset(&stream_requests[0], 0, sizeof(stream_requests[0]));
    listener.count = 0;
    CHECK(ker_tcp_listener_cleanup(&listener) == 0);
    config.time_wait_ms = 0;
    custom_isn = false;
    config.receive_storage = NULL; config.receive_storage_size = 0; config.receive_capacity = 0;
    config.send_storage = NULL; config.send_storage_size = 0; config.send_capacity = 0;
    config.reorder_storage = NULL; config.reorder_storage_size = 0;
    config.window = 1024;
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        requests, 1, &config, 500) == 0);
}
int main(int argc, char **argv)
{
    CHECK(argc == 1 || argc == 2 || argc == 3);
    if (argc >= 2) {
        char *end; errno = 0; long fd = strtol(argv[1], &end, 10);
        CHECK(!errno && end != argv[1] && !*end && fd >= 0 && fd <= INT_MAX);
        tap = (int)fd; CHECK(fcntl(tap, F_SETFL, O_NONBLOCK) == 0);
        host_server_first = argc == 3 && !strcmp(argv[2], "server-first");
        host_reorder_mode = argc == 3 && !strcmp(argv[2], "reorder");
        host_persist_mode = argc == 3 && !strcmp(argv[2], "persist");
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
        .mss = host_reorder_mode ? 256 : 1460, .ttl = 64, .retry_ms = tap < 0 ? 10 : 100,
        .timeout_ms = tap < 0 ? 30 : host_persist_mode ? 30000 : 3000, .next_isn = next_isn,
        .receive_storage = tap < 0 ? NULL : host_storage,
        .receive_storage_size = tap < 0 ? 0 : sizeof(host_storage),
        .receive_capacity = tap < 0 ? 0 : sizeof(host_storage)};
    if (tap >= 0) {
        config.send_storage = host_send_storage;
        config.send_storage_size = sizeof(host_send_storage);
        config.send_capacity = sizeof(host_send_storage);
        config.time_wait_ms = 50;
        config.zero_window_probe = host_persist_mode;
        if (host_reorder_mode) {
            config.reorder_storage = host_reorder_storage;
            config.reorder_storage_size = sizeof(host_reorder_storage);
        }
    }
    CHECK(ker_tcp_listener_init(&listener, &receiver, &neighbors, peer_ip, &tx,
        requests, 1, &config, tap < 0 ? 100 : now_ms()) == 0);
    CHECK(ker_arp_responder_register(&arp, &runtime, &address, &tx) == 0);
    if (tap < 0) { test_listener(); test_stream(); test_passive_close(); }
    else test_host();
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
    puts("bounded TCP passive receive passed");
    return 0;
}
