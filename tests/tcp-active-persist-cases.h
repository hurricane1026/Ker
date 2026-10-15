static unsigned char persist_send[512], persist_receive[1024];
static bool host_zero_window_seen, host_probe_sent, host_reopen_dropped, host_recovered;
static uint32_t host_probe_sequence, host_reopen_ack;
static uint16_t host_reopen_window, host_recovery_window;

static void test_host(void)
{
    const unsigned int goal = 65536;
    unsigned int total = 0, echoed = 0;
    uint64_t deadline = now_ms() + 25000;
    bool reset = false;
    while (!reset || tx.packets) {
        uint64_t now = now_ms(); CHECK(now < deadline);
        CHECK(ker_tcp_active_poll(&active, now) >= 0);
        int sent = ker_tx_export_poll(&tx, 8); CHECK(sent >= 0 || sent == -EAGAIN);
        unsigned char bytes[2048]; ssize_t n = read(tap, bytes, sizeof(bytes));
        if (n < 0) CHECK(errno == EAGAIN || errno == EINTR);
        if (n > 0) {
            size_t length = (size_t)n;
            bool drop = false;
            bool recovery_candidate = false;
            uint32_t recovery_ack = 0;
            if (length >= 54 && bytes[12] == 8 && bytes[13] == 0 && bytes[23] == 6 &&
                bytes[26] == 192 && bytes[27] == 0 && bytes[28] == 2 && bytes[29] == 2 &&
                bytes[30] == 192 && bytes[31] == 0 && bytes[32] == 2 && bytes[33] == 1) {
                size_t ihl = (size_t)(bytes[14] & 15) * 4, tcp = 14 + ihl;
                size_t ip_length = ((size_t)bytes[16] << 8) | bytes[17];
                if ((bytes[14] >> 4) == 4 && ihl >= 20 && ip_length >= ihl + 20 &&
                    ip_length <= length - 14 && tcp + 20 <= 14 + ip_length &&
                    bytes[tcp] == 0x1f && bytes[tcp + 1] == 0x40 &&
                    bytes[tcp + 2] == 0x23 && bytes[tcp + 3] == 0x28 &&
                    (bytes[tcp + 12] >> 4) >= 5 &&
                    tcp + (((size_t)bytes[tcp + 12] >> 4) * 4) <= 14 + ip_length) {
                    unsigned int window = ((unsigned int)bytes[tcp + 14] << 8) | bytes[tcp + 15];
                    uint32_t ack = ((uint32_t)bytes[tcp + 8] << 24) |
                        ((uint32_t)bytes[tcp + 9] << 16) | ((uint32_t)bytes[tcp + 10] << 8) | bytes[tcp + 11];
                    uint32_t packet_seq = ((uint32_t)bytes[tcp + 4] << 24) |
                        ((uint32_t)bytes[tcp + 5] << 16) | ((uint32_t)bytes[tcp + 6] << 8) | bytes[tcp + 7];
                    if (active.status.peer_window == 0 && host_probe_sent && !host_reopen_dropped &&
                        window && ack == host_probe_sequence && packet_seq == active.status.receive_next &&
                        bytes[tcp + 13] == KER_TCP_ACK) {
                        host_reopen_ack = ack; host_reopen_window = (uint16_t)window;
                        host_reopen_dropped = true; drop = true;
                    }
                    if (!drop && host_reopen_dropped && active.status.send_bytes &&
                        active.status.peer_window == 0 && window && ack == active.status.send_next &&
                        packet_seq == active.status.receive_next && bytes[tcp + 13] == KER_TCP_ACK &&
                        ack == host_probe_sequence + 1U) {
                        recovery_candidate = true; recovery_ack = ack;
                        host_recovery_window = (uint16_t)window;
                    }
                }
            }
            if (!drop) {
                struct rte_mbuf *m = ker_packet_alloc(&pool); CHECK(m);
                void *data = rte_pktmbuf_append(m, (uint16_t)length); CHECK(data);
                memcpy(data, bytes, length); dispatch(m);
                if (active.status.peer_window == 0) host_zero_window_seen = true;
                if (recovery_candidate) {
                    CHECK(!active.status.send_bytes && active.status.send_unacknowledged == recovery_ack &&
                        active.status.peer_window == host_recovery_window &&
                        active.send_right == recovery_ack + host_recovery_window);
                    host_recovered = true;
                }
            }
        }
        if (active.status.state == KER_TCP_ACTIVE_READY && !reset) {
            if (total < goal) {
                unsigned char data[512]; unsigned int count = goal - total;
                if (count > sizeof(data)) count = sizeof(data);
                for (unsigned int i = 0; i < count; ++i) data[i] = (total + i) % 251;
                bool zero = active.status.peer_window == 0;
                int accepted = ker_tcp_active_write(&active, data, count);
                CHECK(accepted > 0 || accepted == -EAGAIN || accepted == -ENOSPC);
                if (accepted > 0) {
                    total += (unsigned int)accepted;
                    if (zero && !host_probe_sent) {
                        host_probe_sent = true; host_probe_sequence = active.status.send_unacknowledged;
                    }
                }
            }
            unsigned char out[257];
            for (;;) {
                int received = ker_tcp_active_read(&active, out, sizeof(out));
                if (received == -EAGAIN) break;
                CHECK(received > 0);
                for (int i = 0; i < received; ++i) CHECK(out[i] == echoed++ % 251);
            }
            if (echoed == goal && !active.status.send_bytes) {
                CHECK(ker_tcp_active_reset(&active) == 0); reset = true;
            }
        }
        if (reset && !tx.packets) break;
        struct pollfd p = {.fd = tap, .events = POLLIN}; CHECK(poll(&p, 1, 1) >= 0 || errno == EINTR);
    }
    CHECK(total == goal && echoed == goal && host_zero_window_seen && host_probe_sent &&
        host_reopen_dropped && host_recovered && host_reopen_window && arp.replies_enqueued);
}

static void persist_wire(uint32_t seq, const unsigned char *data, uint16_t length)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL; CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(be32(tcp + 4) == seq && be32(tcp + 8) == 0);
    CHECK(tcp[13] == (KER_TCP_ACK | KER_TCP_PSH));
    CHECK(frame->pkt_len == 54U + length && !memcmp(tcp + 20, data, length));
    ker_packet_free(frame);
}
static void persist_reset(uint32_t seq)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL; CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == (KER_TCP_RST | KER_TCP_ACK) && be32(tcp + 4) == seq);
    ker_packet_free(frame);
}

static void set_zero_window(void)
{
    injected_window = 0;
    inject(0, 0, KER_TCP_ACK, NULL, 0);
    CHECK(!active.status.peer_window && active.send_right == active.status.send_next);
}

static void establish_zero_window(void)
{
    drain(KER_TCP_SYN);
    inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0);
    drain(KER_TCP_ACK);
    set_zero_window();
}

static void test_active(void)
{
    const unsigned char bytes[] = {0xa1, 0xb2, 0xc3};
    establish_zero_window();
    CHECK(ker_tcp_active_shutdown_write(&active) == -EAGAIN);
    active.config.zero_window_probe = false;
    CHECK(ker_tcp_active_write(&active, bytes, sizeof(bytes)) == -EAGAIN);
    active.config.zero_window_probe = true;
    active.status.send_next = active.status.send_unacknowledged = 7;
    active.send_right = 6;
    uint16_t queued_before = tx.packets;
    CHECK(ker_tcp_active_write(&active, bytes, sizeof(bytes)) == -EAGAIN);
    CHECK(!active.status.send_bytes && active.status.send_next == 7 &&
        active.status.send_unacknowledged == 7 && active.send_right == 6 &&
        tx.packets == queued_before && !active.send_deadline_ms);
    CHECK(ker_tcp_active_reset(&active) == 0); persist_reset(7);
    CHECK(ker_tcp_active_cleanup(&active) == 0);

    start(150); establish_zero_window();
    fill_tx(); fill_tx(); memset(persist_send, 0x5a, sizeof(persist_send));
    CHECK(ker_tcp_active_write(&active, bytes, sizeof(bytes)) == -ENOSPC);
    CHECK(!active.status.send_bytes && active.status.send_next == 0 &&
        active.status.send_unacknowledged == 0 && !active.send_deadline_ms &&
        persist_send[0] == 0x5a);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_active_write(&active, bytes, sizeof(bytes)) == 1);
    persist_wire(0, bytes, 1);
    CHECK(active.status.send_bytes == 1 && active.status.send_next == 1 &&
        active.status.send_unacknowledged == 0 && persist_send[0] == bytes[0]);
    uint64_t deadline = active.send_deadline_ms, retry = active.send_retry_ms;
    uint64_t backoff = active.send_backoff_ms;
    inject(0, 0, KER_TCP_ACK, NULL, 0); /* UNA while zero-window probe is unacknowledged. */
    CHECK(active.status.send_bytes == 1 && active.status.send_next == 1 &&
        active.send_deadline_ms == deadline && active.send_retry_ms == retry &&
        active.send_backoff_ms == backoff);
    active.send_right = UINT32_MAX;
    CHECK(ker_tcp_active_write(&active, bytes, sizeof(bytes)) == -EAGAIN);
    active.send_right = 0;
    injected_window = 2;
    inject(0, 0, KER_TCP_ACK, NULL, 0); /* Open window without acknowledging byte. */
    CHECK(active.status.send_bytes == 1 && active.status.peer_window == 2 &&
        active.send_right == 2 && active.send_deadline_ms == deadline &&
        active.send_retry_ms == retry && active.send_backoff_ms == backoff);
    CHECK(ker_tcp_active_poll(&active, retry) == 1);
    persist_wire(0, bytes, 1);
    CHECK(active.send_deadline_ms == deadline && active.send_backoff_ms == 20);
    inject(0, 2, KER_TCP_ACK, NULL, 0); /* Future ACK is rejected. */
    CHECK(active.status.send_bytes == 1 && active.status.send_unacknowledged == 0);
    inject(UINT32_MAX, 1, KER_TCP_ACK, NULL, 0); /* Stale receive sequence is rejected. */
    CHECK(active.status.send_bytes == 1 && active.status.peer_window == 2 && active.send_right == 2);
    inject(0, 1, KER_TCP_ACK, NULL, 0); /* ACK==NXT retires the real byte. */
    CHECK(!active.status.send_bytes && active.status.send_unacknowledged == 1);
    CHECK(!active.send_deadline_ms && !active.send_retry_ms && !active.send_backoff_ms);
    CHECK(ker_tcp_active_reset(&active) == 0); persist_reset(1);
    CHECK(ker_tcp_active_cleanup(&active) == 0);

    start(200); establish_zero_window();
    active.status.send_next = active.status.send_unacknowledged = UINT32_MAX;
    active.send_right = UINT32_MAX;
    CHECK(ker_tcp_active_write(&active, bytes, sizeof(bytes)) == 1);
    persist_wire(UINT32_MAX, bytes, 1);
    inject(0, UINT32_MAX, KER_TCP_ACK, NULL, 0);
    CHECK(active.status.send_bytes == 1 && active.status.send_next == 0);
    inject(0, 0, KER_TCP_ACK, NULL, 0);
    CHECK(!active.status.send_bytes && active.status.send_unacknowledged == 0);
    CHECK(ker_tcp_active_reset(&active) == 0); persist_reset(0);
    CHECK(ker_tcp_active_cleanup(&active) == 0);

    start(300); establish_zero_window();
    CHECK(ker_tcp_active_write(&active, bytes, sizeof(bytes)) == 1);
    persist_wire(0, bytes, 1);
    uint64_t send_deadline = active.send_deadline_ms;
    active.now_ms = send_deadline; /* Exercise receive-side expiry before ACK processing. */
    active.status.peer_window = 0;
    active.send_right = 0;
    injected_window = 1024;
    inject(0, 1, KER_TCP_ACK, NULL, 0);
    CHECK(active.status.state == KER_TCP_ACTIVE_FAILED && active.status.error == -ETIMEDOUT);
    uint32_t expired_next = active.status.send_next, expired_una = active.status.send_unacknowledged;
    uint32_t expired_right = active.send_right;
    uint16_t expired_window = active.status.peer_window;
    inject(0, 1, KER_TCP_ACK, NULL, 0);
    CHECK(active.status.state == KER_TCP_ACTIVE_FAILED && !active.status.send_bytes &&
        active.status.send_next == expired_next && active.status.send_unacknowledged == expired_una &&
        active.send_right == expired_right && active.status.peer_window == expired_window);
}
