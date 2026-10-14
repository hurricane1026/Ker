/* Uses the active handshake fixture for independent wire-level assertions. */
static unsigned char stream_ring[1024];
static void stream_ack(uint32_t ack, uint16_t window, uint8_t flags)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL; CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == flags && be32(tcp + 8) == ack);
    CHECK((((unsigned int)tcp[14] << 8) | tcp[15]) == window);
    ker_packet_free(frame);
}
static void test_active(void)
{
    drain(KER_TCP_SYN);
    inject(UINT32_MAX - 3U, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0);
    stream_ack(UINT32_MAX - 2U, 16, KER_TCP_ACK);
    unsigned char data[32]; for (unsigned int i = 0; i < sizeof(data); ++i) data[i] = i;
    uint32_t seq = UINT32_MAX - 2U;
    inject(seq + 4, 0, KER_TCP_ACK, data, 4); /* Future gap. */
    stream_ack(seq, 16, KER_TCP_ACK); CHECK(!active.status.receive_bytes);
    inject(seq, 1, KER_TCP_ACK, data, 4); CHECK(!tx.packets); /* Bad ACK. */
    fill_tx(); fill_tx();
    inject(seq, 0, KER_TCP_ACK | KER_TCP_PSH, data, 10);
    CHECK(active.status.receive_bytes == 10 && active.status.receive_next == seq + 10);
    CHECK(active.status.ack_pending && active.status.last_tx_error == -ENOSPC);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_active_poll(&active, 101) == 1);
    stream_ack(seq + 10, 6, KER_TCP_ACK);
    inject(seq, 0, KER_TCP_ACK, data, 10); /* Full duplicate, wraparound. */
    stream_ack(seq + 10, 6, KER_TCP_ACK); CHECK(active.status.receive_bytes == 10);
    inject(seq + 8, 0, KER_TCP_ACK, data + 8, 12); /* Both-edge overlap clipped to window. */
    stream_ack(seq + 16, 0, KER_TCP_ACK); CHECK(active.status.receive_bytes == 16);
    inject(seq, 0, KER_TCP_ACK, data, 16); /* Duplicate with full ring. */
    CHECK(receiver.validation_error == 0 && active.status.receive_bytes == 16);
    stream_ack(seq + 16, 0, KER_TCP_ACK);
    inject(seq + 16, 0, KER_TCP_ACK, data + 16, 1); /* Zero window. */
    stream_ack(seq + 16, 0, KER_TCP_ACK);
    unsigned char out[32]; memset(out, 99, sizeof(out));
    CHECK(ker_tcp_active_read(&active, NULL, 1) == -EINVAL && active.status.receive_bytes == 16);
    CHECK(ker_tcp_active_read(&active, out, 10) == 10 && !memcmp(out, data, 10));
    fill_tx(); fill_tx(); CHECK(ker_tcp_active_poll(&active, 102) == 1 && active.status.ack_pending);
    inject(seq + 16, 0, KER_TCP_ACK, data + 16, 6); /* Freed but not yet advertised. */
    CHECK(active.status.receive_bytes == 6 && active.status.receive_next == seq + 16);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_active_poll(&active, 103) == 1); stream_ack(seq + 16, 10, KER_TCP_ACK);
    inject(seq + 16, 0, KER_TCP_ACK, data + 16, 10);
    stream_ack(seq + 26, 0, KER_TCP_ACK); /* Physical ring wraps. */
    CHECK(ker_tcp_active_read(&active, out, sizeof(out)) == 16 && !memcmp(out, data + 10, 16));
    memset(out, 99, sizeof(out)); CHECK(ker_tcp_active_read(&active, out, sizeof(out)) == -EAGAIN && out[0] == 99);
    CHECK(ker_tcp_active_poll(&active, 104) == 1); stream_ack(seq + 26, 16, KER_TCP_ACK);
    inject(seq + 26, 0, KER_TCP_ACK, data, 2); stream_ack(seq + 28, 14, KER_TCP_ACK);
    inject(seq + 27, 0, KER_TCP_RST, NULL, 0); CHECK(active.status.receive_bytes == 2);
    inject(seq + 28, 0, KER_TCP_RST, NULL, 0);
    CHECK(!active.status.receive_bytes && !active.status.ack_pending && ker_tcp_active_read(&active, out, 1) == -ECONNRESET);
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    start(200); drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0);
    stream_ack(0, 16, KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK | KER_TCP_FIN, data, 2);
    CHECK(active.status.state == KER_TCP_ACTIVE_RESET && !active.status.receive_bytes && !active.status.ack_pending);
    stream_ack(0, 16, KER_TCP_RST | KER_TCP_ACK);
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    config.receive_capacity = 15;
    CHECK(ker_tcp_active_start(&active, &receiver, &neighbors, peer_ip, &tx, &config, 300) == -EINVAL);
    config.receive_capacity = 16;
    start(300); drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0);
    stream_ack(0, 16, KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK, data, 2); stream_ack(2, 14, KER_TCP_ACK);
    fill_tx(); fill_tx();
    inject(1, 0, KER_TCP_ACK | KER_TCP_FIN, data + 1, 2); /* Old-overlap FIN, no data retention. */
    CHECK(active.status.state == KER_TCP_ACTIVE_READY && active.status.receive_bytes == 2);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    inject(1, 0, KER_TCP_ACK | KER_TCP_FIN, data + 1, 2);
    CHECK(active.status.state == KER_TCP_ACTIVE_RESET && !active.status.receive_bytes && !active.status.ack_pending);
    stream_ack(2, 14, KER_TCP_RST | KER_TCP_ACK);
}
static void test_host(void)
{
    uint64_t deadline = now_ms() + 10000, read_at = 0;
    unsigned int total = 0; bool reset = false, stalled = false;
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
        if (!stalled && active.status.receive_bytes == sizeof(stream_ring)) {
            stalled = true; read_at = now + 200;
        }
        if (stalled && now >= read_at && !reset) {
            unsigned char out[7]; int received = ker_tcp_active_read(&active, out, sizeof(out));
            CHECK(received > 0 || received == -EAGAIN);
            if (received > 0) for (int i = 0; i < received; ++i) CHECK(out[i] == total++ % 251);
            if (total == 8192) { CHECK(ker_tcp_active_reset(&active) == 0); reset = true; }
        }
        if (reset && !tx.packets) break;
        struct pollfd p = {.fd = tap, .events = POLLIN}; CHECK(poll(&p, 1, 1) >= 0 || errno == EINTR);
    }
    CHECK(stalled && total == 8192 && arp.replies_enqueued > 0);
}
