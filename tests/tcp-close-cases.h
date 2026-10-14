static unsigned char close_receive[1024], close_send[512];
static void wire_control(uint32_t seq, uint32_t ack, uint8_t flags)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL; CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == flags && be32(tcp + 4) == seq && be32(tcp + 8) == ack);
    ker_packet_free(frame);
}
static void open_again(uint64_t now)
{
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    start(now); drain(KER_TCP_SYN);
    inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
}
static void test_active(void)
{
    unsigned char data[4] = {1, 0, 3, 255}, out[4] = {9, 9, 9, 9};
    /* A first FIN may overlap already received data and still acknowledge our FIN. */
    drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    active.config.retry_ms = active.config.timeout_ms = 30;
    inject(0, 0, KER_TCP_ACK | KER_TCP_PSH, data, sizeof(data)); wire_control(0, 4, KER_TCP_ACK);
    CHECK(active.status.receive_bytes == sizeof(data) && active.status.receive_next == 4);
    CHECK(ker_tcp_active_shutdown_write(&active) == 0); wire_control(0, 4, KER_TCP_FIN | KER_TCP_ACK);
    inject(100, 1, KER_TCP_ACK | KER_TCP_FIN, NULL, 0); wire_control(1, 4, KER_TCP_ACK);
    inject(UINT32_MAX - 1U, 1, KER_TCP_ACK | KER_TCP_FIN, data, 1); wire_control(1, 4, KER_TCP_ACK);
    CHECK(!active.status.local_fin_acked && !active.status.peer_eof &&
          active.status.receive_next == 4 && active.status.receive_bytes == sizeof(data));
    inject(0, 1, KER_TCP_ACK | KER_TCP_FIN, data, sizeof(data));
    CHECK(active.status.local_fin_acked && active.status.peer_eof &&
          active.status.state == KER_TCP_ACTIVE_TIME_WAIT && active.status.receive_next == 5 &&
          active.status.receive_bytes == sizeof(data));
    wire_control(1, 5, KER_TCP_ACK);
    inject(0, 1, KER_TCP_ACK | KER_TCP_FIN, data, sizeof(data)); wire_control(1, 5, KER_TCP_ACK);
    CHECK(active.status.receive_next == 5 && active.status.receive_bytes == sizeof(data));
    CHECK(ker_tcp_active_poll(&active, active.close_deadline_ms) == 0 && !tx.packets);
    CHECK(ker_tcp_active_read(&active, out, sizeof(out)) == sizeof(out) && !memcmp(out, data, sizeof(data)));
    if (active.status.ack_pending) {
        CHECK(ker_tcp_active_poll(&active, active.now_ms) == 1);
        wire_control(1, 5, KER_TCP_ACK);
    }
    CHECK(ker_tcp_active_poll(&active, active.time_wait_deadline_ms) == 1);
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    start(100);
    CHECK(ker_tcp_active_shutdown_write(&active) == -ENOTCONN);
    drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    fill_tx(); fill_tx();
    CHECK(ker_tcp_active_shutdown_write(&active) == -ENOSPC && !active.status.local_fin && !active.status.send_next);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    injected_window = 0; inject(0, 0, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_active_shutdown_write(&active) == -EAGAIN && !active.close_deadline_ms);
    injected_window = 1024; inject(0, 0, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_active_shutdown_write(&active) == 0);
    CHECK(active.status.state == KER_TCP_ACTIVE_FIN_WAIT_1 && active.status.send_next == 1);
    wire_control(0, 0, KER_TCP_FIN | KER_TCP_ACK);
    CHECK(ker_tcp_active_shutdown_write(&active) == -EALREADY && ker_tcp_active_write(&active, data, 4) == -EPIPE);
    inject(0, 2, KER_TCP_ACK, NULL, 0); CHECK(!active.status.local_fin_acked);
    CHECK(ker_tcp_active_poll(&active, 110) == 1); wire_control(0, 0, KER_TCP_FIN | KER_TCP_ACK);
    CHECK(active.send_retry_ms == 130 && active.close_deadline_ms == 130);
    inject(0, 1, KER_TCP_ACK, NULL, 0); CHECK(active.status.state == KER_TCP_ACTIVE_FIN_WAIT_2);
    CHECK(ker_tcp_active_poll(&active, 130) == 1 && active.status.error == -ETIMEDOUT);
    open_again(200);
    /* Data+FIN is retained before EOF even when its ACK cannot be admitted. */
    fill_tx(); fill_tx(); inject(0, 0, KER_TCP_ACK | KER_TCP_FIN, data, 4);
    CHECK(active.status.state == KER_TCP_ACTIVE_CLOSE_WAIT && active.status.peer_eof);
    CHECK(active.status.receive_next == 5 && active.status.receive_bytes == 4 && active.status.ack_pending);
    CHECK(ker_tcp_active_read(&active, out, 2) == 2 && !memcmp(out, data, 2));
    CHECK(ker_tcp_active_read(&active, out + 2, 2) == 2 && !memcmp(out, data, 4));
    CHECK(ker_tcp_active_read(&active, out, 4) == 0 && out[0] == 1);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_active_poll(&active, 201) == 1); wire_control(0, 5, KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK | KER_TCP_FIN, data, 4); wire_control(0, 5, KER_TCP_ACK);
    CHECK(active.status.receive_next == 5 && !active.status.receive_bytes);
    inject(5, 0, KER_TCP_ACK, data, 4); wire_control(0, 5, KER_TCP_ACK); CHECK(!active.status.receive_bytes);
    CHECK(ker_tcp_active_write(&active, data, 4) == 4);
    CHECK(ker_tcp_active_shutdown_write(&active) == -EAGAIN); wire_control(0, 5, KER_TCP_ACK | KER_TCP_PSH);
    inject(5, 4, KER_TCP_ACK, NULL, 0);
    CHECK(ker_tcp_active_shutdown_write(&active) == 0 && active.status.state == KER_TCP_ACTIVE_LAST_ACK);
    wire_control(4, 5, KER_TCP_FIN | KER_TCP_ACK);
    inject(5, 4, KER_TCP_ACK, NULL, 0); CHECK(active.status.state == KER_TCP_ACTIVE_LAST_ACK);
    inject(5, 5, KER_TCP_ACK, NULL, 0); CHECK(active.status.state == KER_TCP_ACTIVE_CLOSED);
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    start(300); drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    /* Future FIN does not produce EOF. Simultaneous close then duplicate FIN+ACK. */
    inject(3, 0, KER_TCP_ACK | KER_TCP_FIN, NULL, 0); drain(KER_TCP_ACK); CHECK(!active.status.peer_eof);
    CHECK(ker_tcp_active_shutdown_write(&active) == 0); wire_control(0, 0, KER_TCP_FIN | KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK | KER_TCP_FIN, NULL, 0); wire_control(1, 1, KER_TCP_ACK);
    CHECK(active.status.state == KER_TCP_ACTIVE_CLOSING);
    inject(0, 1, KER_TCP_ACK | KER_TCP_FIN, NULL, 0); wire_control(1, 1, KER_TCP_ACK);
    CHECK(active.status.state == KER_TCP_ACTIVE_TIME_WAIT && active.status.receive_next == 1);
    uint64_t expires = active.time_wait_deadline_ms;
    uint32_t send_right = active.send_right, una = active.status.send_unacknowledged;
    uint16_t window = active.status.peer_window;
    injected_window = 17; inject(1, 1, KER_TCP_ACK, NULL, 0);
    CHECK(active.send_right == send_right && active.status.peer_window == window && active.status.send_unacknowledged == una);
    CHECK(active.status.peer_eof && active.status.local_fin && active.status.local_fin_acked);
    injected_window = 1024;
    inject(1, 1, KER_TCP_RST, NULL, 0); CHECK(active.status.state == KER_TCP_ACTIVE_TIME_WAIT);
    inject(1, 1, KER_TCP_ACK | KER_TCP_FIN | KER_TCP_ECE, data, 4);
    CHECK(active.status.state == KER_TCP_ACTIVE_TIME_WAIT && !tx.packets);
    CHECK(ker_tcp_active_reset(&active) == -EBUSY && ker_tcp_active_cleanup(&active) == -EBUSY);
    inject(0, 1, KER_TCP_ACK | KER_TCP_FIN, NULL, 0); wire_control(1, 1, KER_TCP_ACK);
    CHECK(active.time_wait_deadline_ms == expires);
    fill_tx(); fill_tx(); inject(0, 1, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    CHECK(active.status.ack_pending && active.time_wait_deadline_ms == expires);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_active_poll(&active, 301) == 1); wire_control(1, 1, KER_TCP_ACK);
    CHECK(!active.status.ack_pending && active.time_wait_deadline_ms == expires);
    CHECK(ker_tcp_active_poll(&active, expires - 1) == 0);
    CHECK(ker_tcp_active_poll(&active, expires - 2) == -EINVAL);
    CHECK(ker_tcp_active_poll(&active, expires) == 1 && active.status.state == KER_TCP_ACTIVE_CLOSED);
    open_again(expires + 1);
    CHECK(ker_tcp_active_shutdown_write(&active) == 0); wire_control(0, 0, KER_TCP_FIN | KER_TCP_ACK);
    /* Combined ACK+payload+FIN directly enters TIME_WAIT, but unread storage pins cleanup. */
    inject(0, 1, KER_TCP_ACK | KER_TCP_FIN, data, 4); wire_control(1, 5, KER_TCP_ACK);
    CHECK(active.status.state == KER_TCP_ACTIVE_TIME_WAIT && active.status.receive_bytes == 4);
    CHECK(ker_tcp_active_poll(&active, active.time_wait_deadline_ms) == 1);
    CHECK(ker_tcp_active_cleanup(&active) == -EBUSY);
    CHECK(ker_tcp_active_read(&active, out, 4) == 4 && !memcmp(out, data, 4));
    CHECK(ker_tcp_active_cleanup(&active) == -EBUSY); /* Pending window ACK. */
    CHECK(ker_tcp_active_poll(&active, active.now_ms) == 1); wire_control(1, 5, KER_TCP_ACK);
    uint64_t now = active.now_ms + 1;
    open_again(now);
    active.status.send_unacknowledged = active.status.send_next = UINT32_MAX;
    active.send_right = 1023;
    CHECK(ker_tcp_active_shutdown_write(&active) == 0); wire_control(UINT32_MAX, 0, KER_TCP_FIN | KER_TCP_ACK);
    inject(0, 0, KER_TCP_ACK | KER_TCP_FIN, NULL, 0); wire_control(0, 1, KER_TCP_ACK);
    CHECK(active.status.local_fin_acked && active.status.state == KER_TCP_ACTIVE_TIME_WAIT);
    CHECK(ker_tcp_active_poll(&active, active.time_wait_deadline_ms) == 1);
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    config.timeout_ms = 60;
    start(500); drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    CHECK(ker_tcp_active_shutdown_write(&active) == 0); wire_control(0, 0, KER_TCP_FIN | KER_TCP_ACK);
    fill_tx(); fill_tx();
    CHECK(ker_tcp_active_poll(&active, 510) == 1 && active.status.last_tx_error == -ENOSPC);
    CHECK(active.close_deadline_ms == 560 && active.send_retry_ms == 530);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_active_poll(&active, 529) == 0);
    CHECK(ker_tcp_active_poll(&active, 530) == 1); wire_control(0, 0, KER_TCP_FIN | KER_TCP_ACK);
    CHECK(ker_tcp_active_poll(&active, 560) == 1 && active.status.error == -ETIMEDOUT);
    inject(0, 1, KER_TCP_ACK | KER_TCP_FIN, NULL, 0); CHECK(active.status.state == KER_TCP_ACTIVE_FAILED);
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    config.timeout_ms = 30;
    config.time_wait_ms = 0;
    start(100); drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    CHECK(ker_tcp_active_shutdown_write(&active) == -EOPNOTSUPP);
    inject(0, 0, KER_TCP_ACK | KER_TCP_FIN, NULL, 0);
    CHECK(active.status.state == KER_TCP_ACTIVE_RESET && active.status.error == -EOPNOTSUPP);
    drain(KER_TCP_RST | KER_TCP_ACK); CHECK(ker_tcp_active_cleanup(&active) == 0);
    config.time_wait_ms = 120000;
    start(UINT64_MAX - 40); drain(KER_TCP_SYN);
    inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    CHECK(ker_tcp_active_poll(&active, UINT64_MAX - 20) == 0);
    CHECK(ker_tcp_active_shutdown_write(&active) == -EOVERFLOW && !active.status.local_fin && !active.status.send_next);
    CHECK(ker_tcp_active_reset(&active) == 0); drain(KER_TCP_RST | KER_TCP_ACK);
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    config.time_wait_ms = UINT64_MAX;
    start(100); drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    CHECK(ker_tcp_active_shutdown_write(&active) == 0); wire_control(0, 0, KER_TCP_FIN | KER_TCP_ACK);
    inject(0, 1, KER_TCP_ACK | KER_TCP_FIN, NULL, 0); wire_control(1, 1, KER_TCP_ACK);
    CHECK(active.time_wait_saturated && ker_tcp_active_poll(&active, UINT64_MAX) == 0);
    CHECK(ker_tcp_active_cleanup(&active) == -EBUSY && ker_tcp_active_reset(&active) == -EBUSY);
    /* Test-only restoration permits fixture resource accounting; no production escape. */
    active.time_wait_saturated = false;
    CHECK(ker_tcp_active_poll(&active, UINT64_MAX) == 1);

    /* An accepted EOF with a nearly full ring still ACKs later payload without
     * changing sequence space or unread bytes, even while TX is backpressured. */
    unsigned char full_data[1023], received_data[1023];
    for (size_t i = 0; i < sizeof(full_data); ++i) full_data[i] = (unsigned char)i;
    open_again(200);
    fill_tx(); fill_tx();
    inject(0, 0, KER_TCP_ACK | KER_TCP_FIN, full_data, sizeof(full_data));
    CHECK(active.status.peer_eof && active.status.receive_next == 1024 &&
          active.status.receive_bytes == sizeof(full_data) &&
          active.status.ack_pending && active.status.last_tx_error == -ENOSPC);
    unsigned char extra[4] = {9, 8, 7, 6};
    inject(1024, 0, KER_TCP_ACK, extra, sizeof(extra));
    CHECK(active.status.peer_eof && active.status.receive_next == 1024 &&
          active.status.receive_bytes == sizeof(full_data) &&
          active.status.ack_pending && active.status.last_tx_error == -ENOSPC);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_active_poll(&active, active.now_ms) == 1);
    wire_control(0, 1024, KER_TCP_ACK);
    CHECK(!active.status.ack_pending && active.status.receive_next == 1024 &&
          active.status.receive_bytes == sizeof(full_data));
    CHECK(ker_tcp_active_read(&active, received_data, sizeof(received_data)) ==
          sizeof(received_data));
    CHECK(!memcmp(received_data, full_data, sizeof(full_data)) &&
          active.status.receive_next == 1024 && !active.status.receive_bytes &&
          active.status.peer_eof);
    CHECK(ker_tcp_active_poll(&active, active.now_ms) == 1);
    wire_control(0, 1024, KER_TCP_ACK);
    CHECK(ker_tcp_active_read(&active, received_data, 1) == 0);
    CHECK(ker_tcp_active_shutdown_write(&active) == 0);
    wire_control(0, 1024, KER_TCP_FIN | KER_TCP_ACK);
    inject(1024, 1, KER_TCP_ACK, NULL, 0);
    CHECK(active.status.state == KER_TCP_ACTIVE_CLOSED &&
          active.status.peer_eof && active.status.receive_next == 1024);
}
static void test_host(void)
{
    unsigned int received = 0, sent_total = 0; bool shutdown = false, eof = false;
    uint64_t deadline = now_ms() + 10000;
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
        CHECK(active.status.state != KER_TCP_ACTIVE_FAILED && active.status.state != KER_TCP_ACTIVE_RESET);
        if (active.peer_known) {
            unsigned char out[127]; int count = ker_tcp_active_read(&active, out, sizeof(out));
            CHECK(count >= 0 || count == -EAGAIN);
            if (count > 0) for (int i = 0; i < count; ++i) CHECK(out[i] == received++ % 251);
            if (count == 0) { CHECK(received == 4096); eof = true; }
            if (eof && sent_total < 4096) {
                unsigned char data[512]; for (unsigned int i = 0; i < sizeof(data); ++i) data[i] = (sent_total + i) % 251;
                int accepted = ker_tcp_active_write(&active, data, sizeof(data));
                CHECK(accepted > 0 || accepted == -EAGAIN || accepted == -ENOSPC);
                if (accepted > 0) sent_total += accepted;
            }
            if (sent_total == 4096 && !active.status.send_bytes && !shutdown) {
                int result = ker_tcp_active_shutdown_write(&active);
                CHECK(!result || result == -EAGAIN || result == -ENOSPC); if (!result) shutdown = true;
            }
        }
        if (active.status.state == KER_TCP_ACTIVE_CLOSED && !tx.packets && !active.status.ack_pending) break;
        struct pollfd p = {.fd = tap, .events = POLLIN}; CHECK(poll(&p, 1, 1) >= 0 || errno == EINTR);
    }
    CHECK(eof && shutdown && received == 4096 && sent_total == 4096 && arp.replies_enqueued > 0);
}
