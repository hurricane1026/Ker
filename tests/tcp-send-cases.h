static unsigned char send_storage[512], receive_storage[1024];
static void wire_data(uint32_t sequence, uint32_t ack, const void *expected, uint16_t length)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL; CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(be32(tcp + 4) == sequence && be32(tcp + 8) == ack);
    CHECK(tcp[13] == (KER_TCP_ACK | KER_TCP_PSH));
    CHECK(frame->pkt_len == 54U + length && !memcmp(tcp + 20, expected, length));
    ker_packet_free(frame);
}
static void test_active(void)
{
    unsigned char data[600]; for (unsigned int i = 0; i < sizeof(data); ++i) data[i] = i;
    CHECK(ker_tcp_active_write(&active, data, 4) == -ENOTCONN);
    drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    fill_tx(); fill_tx();
    CHECK(ker_tcp_active_write(&active, data, sizeof(data)) == -ENOSPC);
    CHECK(!active.status.send_bytes && active.status.send_next == 0 && !active.send_deadline_ms);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_active_write(&active, data, sizeof(data)) == 512);
    CHECK(active.status.send_bytes == 512 && active.status.send_next == 512);
    wire_data(0, 0, data, 512);
    CHECK(ker_tcp_active_write(&active, data, 1) == -EAGAIN);
    inject(1, 512, KER_TCP_ACK, NULL, 0); /* Wrong sequence does not free data. */
    inject(0, 513, KER_TCP_ACK, NULL, 0); /* Future ACK. */
    CHECK(active.status.send_bytes == 512);
    inject(0, 100, KER_TCP_ACK, NULL, 0);
    CHECK(active.status.send_bytes == 412 && active.send_head == 100);
    uint64_t deadline = active.send_deadline_ms;
    uint32_t right = active.send_right;
    injected_window = 2; inject(1, 100, KER_TCP_ACK, NULL, 0);
    CHECK(active.send_right == right && active.status.peer_window == 1024 && active.status.send_unacknowledged == 100);
    injected_window = 0; inject(0, 100, KER_TCP_ACK, NULL, 0);
    CHECK(active.send_deadline_ms == deadline && !active.status.peer_window && active.send_right == 100 && active.status.send_unacknowledged == 100);
    unsigned char retained[412]; memcpy(retained, data + 100, sizeof(retained));
    data[100] ^= 0xff; /* Retransmission owns its copy, not the caller's source. */
    CHECK(ker_tcp_active_poll(&active, 110) == 1); wire_data(100, 0, retained, 412);
    data[100] ^= 0xff;
    CHECK(active.send_backoff_ms == 20 && active.send_retry_ms == 130);
    inject(0, 99, KER_TCP_ACK, NULL, 0); CHECK(active.status.send_bytes == 412); /* Old ACK. */
    inject(0, 512, KER_TCP_ACK, NULL, 0); CHECK(!active.status.send_bytes);
    CHECK(ker_tcp_active_write(&active, data, 2) == -EAGAIN && !active.send_deadline_ms);
    injected_window = 2; inject(1, 512, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_active_write(&active, data, 2) == -EAGAIN);
    inject(0, 512, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_active_write(&active, data, 4) == 2); wire_data(512, 0, data, 2);
    injected_window = 1024;
    inject(0, 514, KER_TCP_ACK | KER_TCP_PSH, data, 4); /* ACK and incoming data both processed. */
    CHECK(!active.status.send_bytes && active.status.receive_bytes == 4 && active.status.receive_next == 4);
    /* Drain the cumulative ACK separately: local sequence now includes data. */
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL; CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(be32(tcp + 4) == 514 && be32(tcp + 8) == 4); ker_packet_free(frame);
    unsigned char out[4]; CHECK(ker_tcp_active_read(&active, out, 4) == 4 && !memcmp(out, data, 4));
    CHECK(ker_tcp_active_write(&active, data, 4) == 4);
    CHECK(!active.status.ack_pending && active.receive_right == 1028);
    wire_data(514, 4, data, 4);
    fill_tx(); fill_tx(); CHECK(ker_tcp_active_reset(&active) == -ENOSPC && active.status.send_bytes == 4);
    /* Retry backpressure cannot postpone the absolute timeout. */
    CHECK(ker_tcp_active_poll(&active, 120) == 1 && active.status.last_tx_error == -ENOSPC);
    CHECK(ker_tcp_active_poll(&active, 119) == -EINVAL);
    CHECK(ker_tcp_active_poll(&active, 140) == 1 && active.status.error == -ETIMEDOUT);
    inject(4, 518, KER_TCP_ACK, NULL, 0); CHECK(active.status.state == KER_TCP_ACTIVE_FAILED);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    /* Wraparound partial ACK and sequence-correct RST after a new open. */
    start(200); drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    active.status.send_unacknowledged = active.status.send_next = UINT32_MAX - 1U;
    active.send_right = active.status.send_next + 1024;
    CHECK(ker_tcp_active_write(&active, data, 4) == 4); wire_data(UINT32_MAX - 1U, 0, data, 4);
    inject(0, 0, KER_TCP_ACK, NULL, 0); CHECK(active.status.send_bytes == 2);
    inject(0, 0, KER_TCP_ACK | KER_TCP_PSH, data, 2);
    CHECK(active.status.send_bytes == 2 && active.status.receive_bytes == 2);
    CHECK(ker_tx_export_poll(&tx, 1) == 1); frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1); tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(be32(tcp + 4) == 2 && be32(tcp + 8) == 2); ker_packet_free(frame);
    CHECK(ker_tcp_active_poll(&active, 210) == 1); wire_data(0, 2, data + 2, 2);
    inject(2, 0, KER_TCP_RST, NULL, 0);
    CHECK(!active.status.send_bytes && !active.status.receive_bytes && !active.status.ack_pending && !active.send_deadline_ms);
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    config.mss = 64;
    start(300); drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    CHECK(ker_tcp_active_write(&active, data, sizeof(data)) == 64); wire_data(0, 0, data, 64);
    CHECK(ker_tcp_active_reset(&active) == 0 && !active.status.send_bytes && !active.send_retry_ms);
    CHECK(ker_tx_export_poll(&tx, 1) == 1); frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1); tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == (KER_TCP_RST | KER_TCP_ACK) && be32(tcp + 4) == 64); ker_packet_free(frame);
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    config.retry_ms = UINT64_MAX / 3 - 1; config.timeout_ms = UINT64_MAX;
    start(0); drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    CHECK(ker_tcp_active_write(&active, data, 4) == 4); wire_data(0, 0, data, 4);
    CHECK(ker_tcp_active_poll(&active, config.retry_ms) == 1); wire_data(0, 0, data, 4);
    CHECK(active.send_retry_ms == UINT64_MAX - 3 && active.send_backoff_ms == 2 * config.retry_ms);
    CHECK(ker_tcp_active_poll(&active, UINT64_MAX - 3) == 1); wire_data(0, 0, data, 4);
    CHECK(active.send_backoff_ms == UINT64_MAX && active.send_retry_ms == UINT64_MAX);
    /* A saturated deadline expires before any retry at UINT64_MAX. */
    CHECK(ker_tcp_active_poll(&active, UINT64_MAX) == 1 && active.status.error == -ETIMEDOUT);
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    config.retry_ms = 10; config.timeout_ms = 30;
    start(UINT64_MAX - 40); drain(KER_TCP_SYN);
    inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    CHECK(ker_tcp_active_poll(&active, UINT64_MAX - 20) == 0);
    CHECK(ker_tcp_active_write(&active, data, 4) == -EOVERFLOW && !active.status.send_bytes);
    CHECK(ker_tcp_active_reset(&active) == 0); drain(KER_TCP_RST | KER_TCP_ACK);
}
static void test_host(void)
{
    unsigned int total = 0, echoed = 0;
    uint64_t deadline = now_ms() + 10000; bool reset = false;
    while (true) {
        uint64_t now = now_ms(); CHECK(now < deadline);
        CHECK(ker_tcp_active_poll(&active, now) >= 0);
        int sent = ker_tx_export_poll(&tx, 8); CHECK(sent >= 0 || sent == -EAGAIN);
        unsigned char bytes[2048]; ssize_t n = read(tap, bytes, sizeof(bytes));
        if (n < 0) CHECK(errno == EAGAIN || errno == EINTR);
        if (n > 0) {
            struct rte_mbuf *m = ker_packet_alloc(&pool); CHECK(m);
            void *data = rte_pktmbuf_append(m, (uint16_t)n); CHECK(data);
            memcpy(data, bytes, (size_t)n); dispatch(m);
        }
        CHECK(active.status.state != KER_TCP_ACTIVE_FAILED);
        if (active.status.state == KER_TCP_ACTIVE_READY && !reset) {
            if (total < 8192) {
                unsigned char data[512]; unsigned int length = 8192 - total;
                if (length > sizeof(data)) length = sizeof(data);
                for (unsigned int i = 0; i < length; ++i) data[i] = (total + i) % 251;
                int accepted = ker_tcp_active_write(&active, data, length);
                CHECK(accepted > 0 || accepted == -EAGAIN || accepted == -ENOSPC);
                if (accepted > 0) total += accepted;
            }
            unsigned char out[127]; int received = ker_tcp_active_read(&active, out, sizeof(out));
            CHECK(received > 0 || received == -EAGAIN);
            if (received > 0) for (int i = 0; i < received; ++i) CHECK(out[i] == echoed++ % 251);
            if (echoed == 8192 && !active.status.send_bytes) { CHECK(ker_tcp_active_reset(&active) == 0); reset = true; }
        }
        if (reset && !tx.packets) break;
        struct pollfd p = {.fd = tap, .events = POLLIN}; CHECK(poll(&p, 1, 1) >= 0 || errno == EINTR);
    }
    CHECK(total == 8192 && echoed == 8192 && arp.replies_enqueued > 0);
}
