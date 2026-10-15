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
static void drain_any_reset(void)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL; CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == (KER_TCP_RST | KER_TCP_ACK)); ker_packet_free(frame);
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
    CHECK(ker_tcp_active_reset(&active) == 0); drain_any_reset();
    CHECK(ker_tcp_active_cleanup(&active) == 0);

    /* RFC 6298 DATA estimator: odd samples round conservatively upward. */
    config.retry_ms = 10; config.timeout_ms = 200000; config.adaptive_rto = true;
    config.zero_window_probe = false; config.time_wait_ms = 0; config.mss = 64;
    injected_window = 1024;
    start(1000); drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    CHECK(active.rto_ms == 1000);
    CHECK(ker_tcp_active_write(&active, data, 4) == 4); wire_data(0, 0, data, 4);
    active.now_ms = 1601; inject(0, 4, KER_TCP_ACK, NULL, 0);
    CHECK(active.rtt_srtt_x8 == 4808 && active.rttvar_x8 == 2404 && active.rto_ms == 1803);
    CHECK(ker_tcp_active_write(&active, data + 4, 4) == 4); wire_data(4, 0, data + 4, 4);
    uint64_t window_retry = active.send_retry_ms, window_deadline = active.send_deadline_ms;
    uint64_t window_rto = active.rto_ms, window_first_tx = active.send_first_tx_ms;
    uint64_t window_srtt = active.rtt_srtt_x8, window_rttvar = active.rttvar_x8;
    injected_window = 2; inject(1, 8, KER_TCP_ACK, NULL, 0); /* Future receive sequence. */
    inject(UINT32_MAX, 8, KER_TCP_ACK, NULL, 0); /* Stale receive sequence. */
    CHECK(active.status.send_bytes == 4 && active.status.send_unacknowledged == 4 &&
        active.send_retry_ms == window_retry && active.send_deadline_ms == window_deadline &&
        active.rto_ms == window_rto && active.send_first_tx_ms == window_first_tx &&
        active.rtt_srtt_x8 == window_srtt && active.rttvar_x8 == window_rttvar);
    injected_window = 900; inject(0, 4, KER_TCP_ACK, NULL, 0); /* Eligible ACK==UNA/window update. */
    CHECK(active.status.peer_window == 900 && active.send_right == 904 && active.status.send_bytes == 4 &&
        active.send_retry_ms == window_retry && active.send_deadline_ms == window_deadline &&
        active.rto_ms == window_rto && active.send_first_tx_ms == window_first_tx &&
        active.rtt_srtt_x8 == window_srtt && active.rttvar_x8 == window_rttvar);
    injected_window = 1024;
    active.now_ms = 2203; inject(0, 8, KER_TCP_ACK, NULL, 0);
    CHECK(active.rtt_srtt_x8 == 4809 && active.rttvar_x8 == 1805 && active.rto_ms == 1504);

    /* Partial progress restarts only the remaining suffix timer; duplicates do not. */
    CHECK(ker_tcp_active_write(&active, data + 8, 4) == 4); wire_data(8, 0, data + 8, 4);
    uint64_t rto_deadline = active.send_deadline_ms;
    active.now_ms = 2303; inject(0, 10, KER_TCP_ACK, NULL, 0);
    CHECK(active.status.send_bytes == 2 && active.send_head == 2 && active.send_retry_ms == 3807);
    CHECK(active.send_deadline_ms == rto_deadline && active.rto_ms == 1504);
    uint64_t partial_retry = active.send_retry_ms;
    inject(0, 10, KER_TCP_ACK, NULL, 0);
    CHECK(active.send_retry_ms == partial_retry && active.status.send_bytes == 2);
    CHECK(ker_tcp_active_poll(&active, partial_retry) == 1); wire_data(10, 0, data + 10, 2);
    CHECK(active.send_retransmitted && active.rto_ms == 3008 && active.send_backoff_ms == 3008);
    active.now_ms = partial_retry + 1; inject(0, 12, KER_TCP_ACK, NULL, 0);
    CHECK(!active.status.send_bytes && active.rto_ms == 3008 && active.rtt_srtt_x8 == 4809);

    /* A fresh clean sample collapses backoff; ENOSPC does not trigger Karn. */
    CHECK(ker_tcp_active_write(&active, data + 12, 4) == 4); wire_data(12, 0, data + 12, 4);
    active.now_ms = 4900; inject(0, 16, KER_TCP_ACK, NULL, 0);
    CHECK(active.rtt_srtt_x8 == 5300 && active.rttvar_x8 == 2336 && active.rto_ms == 1831);
    CHECK(ker_tcp_active_write(&active, data + 16, 4) == 4); wire_data(16, 0, data + 16, 4);
    uint64_t enospc_deadline = active.send_deadline_ms;
    fill_tx(); fill_tx();
    CHECK(ker_tcp_active_poll(&active, 6731) == 1 && active.status.last_tx_error == -ENOSPC);
    CHECK(!active.send_retransmitted && active.rto_ms == 1831 && active.send_backoff_ms == 3662);
    CHECK(active.send_deadline_ms == enospc_deadline);
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    active.now_ms = 7200; inject(0, 20, KER_TCP_ACK, NULL, 0);
    CHECK(!active.status.send_bytes && active.rtt_srtt_x8 == 6938 && active.rttvar_x8 == 5027 && active.rto_ms == 3381);

    CHECK(ker_tcp_active_write(&active, data + 20, 4) == 4); wire_data(20, 0, data + 20, 4);
    CHECK(ker_tcp_active_poll(&active, 10581) == 1); wire_data(20, 0, data + 20, 4);
    CHECK(active.rto_ms == 6762 && active.send_retransmitted);
    active.now_ms = 10600; inject(0, 24, KER_TCP_ACK, NULL, 0);
    CHECK(!active.status.send_bytes && active.rto_ms == 6762 && active.rtt_srtt_x8 == 6938);
    CHECK(ker_tcp_active_write(&active, data + 24, 4) == 4); wire_data(24, 0, data + 24, 4);
    active.now_ms = 11600; inject(0, 28, KER_TCP_ACK, NULL, 0);
    CHECK(active.rto_ms < 6762 && active.rtt_srtt_x8 == 7071);

    /* Probe and FIN flights retain their legacy fixed retry policy. */
    config.zero_window_probe = true; active.config.zero_window_probe = true;
    active.send_right = active.status.send_next;
    uint64_t estimator_before_probe = active.rto_ms;
    int probe_write = ker_tcp_active_write(&active, data + 28, 1);
    CHECK(probe_write == 1); wire_data(28, 0, data + 28, 1);
    CHECK(active.send_zero_window_probe && !active.send_rtt_eligible && active.send_backoff_ms == config.retry_ms);
    CHECK(ker_tcp_active_poll(&active, active.send_retry_ms) == 1); wire_data(28, 0, data + 28, 1);
    active.now_ms = active.send_retry_ms; inject(0, 29, KER_TCP_ACK, NULL, 0);
    CHECK(active.rto_ms == estimator_before_probe);
    config.zero_window_probe = false; active.config.zero_window_probe = false;
    config.time_wait_ms = active.config.time_wait_ms = 120000;
    CHECK(ker_tcp_active_shutdown_write(&active) == 0);
    CHECK(active.send_backoff_ms == config.retry_ms);
    CHECK(ker_tx_export_poll(&tx, 1) == 1); frame = NULL;
    CHECK(ker_tx_ring_take(&output, &frame) == 1); tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == (KER_TCP_FIN | KER_TCP_ACK) && be32(tcp + 4) == 29); ker_packet_free(frame);
    CHECK(ker_tcp_active_reset(&active) == 0); drain_any_reset();
    CHECK(ker_tcp_active_cleanup(&active) == 0);

    /* Successful exponential backoff is capped and persists into the next flight. */
    config.time_wait_ms = 0;
    start(20000); drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    CHECK(ker_tcp_active_write(&active, data, 1) == 1); wire_data(0, 0, data, 1);
    for (unsigned int retry = 0; retry < 6; ++retry) {
        uint64_t at = active.send_retry_ms;
        CHECK(ker_tcp_active_poll(&active, at) == 1); wire_data(0, 0, data, 1);
    }
    CHECK(active.rto_ms == 60000 && active.send_backoff_ms == 60000);
    active.now_ms = active.send_retry_ms - 1; inject(0, 1, KER_TCP_ACK, NULL, 0);
    CHECK(!active.status.send_bytes && active.rto_ms == 60000);
    CHECK(ker_tcp_active_write(&active, data + 1, 1) == 1); wire_data(1, 0, data + 1, 1);
    CHECK(active.send_backoff_ms == 60000);
    CHECK(ker_tcp_active_reset(&active) == 0); drain_any_reset(); CHECK(ker_tcp_active_cleanup(&active) == 0);
    config.timeout_ms = 300000;
    uint64_t near_max = UINT64_MAX - 300001;
    start(near_max); drain(KER_TCP_SYN); inject(UINT32_MAX, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0); drain(KER_TCP_ACK);
    CHECK(ker_tcp_active_write(&active, data, 4) == 4); wire_data(0, 0, data, 4);
    CHECK(active.send_deadline_ms == UINT64_MAX - 1);
    uint32_t expiry_una = active.status.send_unacknowledged, expiry_right = active.send_right;
    uint16_t expiry_window = active.status.peer_window;
    active.now_ms = active.send_deadline_ms; inject(0, 4, KER_TCP_ACK, NULL, 0);
    CHECK(active.status.state == KER_TCP_ACTIVE_FAILED && active.status.error == -ETIMEDOUT &&
        !active.status.send_bytes && active.status.send_unacknowledged == expiry_una &&
        active.send_right == expiry_right && active.status.peer_window == expiry_window && !active.rto_ms);
    config.adaptive_rto = false; config.retry_ms = 10; config.timeout_ms = 30;
}
static void test_host(void)
{
    unsigned int total = 0, echoed = 0;
    uint64_t deadline = now_ms() + 10000; bool reset = false;
    while (true) {
        uint64_t now = now_ms(); CHECK(now < deadline);
        CHECK(ker_tcp_active_poll(&active, now) >= 0);
        if (host_rto_mode && host_ack_held && now >= host_release_ack_at) {
            CHECK(active.status.send_bytes == 1 && host_ack_held);
            struct rte_mbuf *held = ker_packet_alloc(&pool); CHECK(held);
            void *dst = rte_pktmbuf_append(held, (uint16_t)host_held_ack_length); CHECK(dst);
            memcpy(dst, host_held_ack, host_held_ack_length); dispatch(held);
            host_ack_held = false; host_ack_released = true;
            CHECK(active.rto_ms > 1000 && !active.status.send_bytes);
            host_rto_stage = 2;
        }
        if (host_rto_mode && host_second_ack_held && now >= host_release_second_ack_at) {
            CHECK(active.status.send_bytes == 1 && host_second_ack_held);
            uint64_t backed_off = active.rto_ms;
            struct rte_mbuf *held = ker_packet_alloc(&pool); CHECK(held);
            void *dst = rte_pktmbuf_append(held, (uint16_t)host_held_second_ack_length); CHECK(dst);
            memcpy(dst, host_held_second_ack, host_held_second_ack_length); dispatch(held);
            host_second_ack_held = false; host_second_ack_released = true;
            CHECK(!active.status.send_bytes && active.rto_ms < backed_off);
            host_relearned = true; host_rto_stage = 7;
        }
        int sent = ker_tx_export_poll(&tx, 8); CHECK(sent >= 0 || sent == -EAGAIN);
        unsigned char bytes[2048]; ssize_t n = read(tap, bytes, sizeof(bytes));
        if (n < 0) CHECK(errno == EAGAIN || errno == EINTR);
        if (n > 0) {
            bool held = false;
            if (host_rto_mode && n >= 54 && bytes[12] == 8 && bytes[13] == 0 &&
                (bytes[14] >> 4) == 4 && bytes[23] == 6) {
                unsigned int ihl = (bytes[14] & 15U) * 4U, th = 14U + ihl;
                unsigned int iplen = ((unsigned int)bytes[16] << 8) | bytes[17];
                if (ihl >= 20 && iplen >= ihl + 20 && iplen <= (size_t)n - 14U &&
                    bytes[26] == 192 && bytes[27] == 0 && bytes[28] == 2 && bytes[29] == 2 &&
                    bytes[30] == 192 && bytes[31] == 0 && bytes[32] == 2 && bytes[33] == 1) {
                    unsigned int tcp_len = ((bytes[th + 12] >> 4) & 15U) * 4U;
                    if (tcp_len < 20 || iplen < ihl + tcp_len) goto no_rto_frame;
                    unsigned int payload = iplen - ihl - tcp_len;
                    uint32_t seq = be32(bytes + th + 4), ack = be32(bytes + th + 8);
                    uint16_t sport = ((uint16_t)bytes[th] << 8) | bytes[th + 1];
                    uint16_t dport = ((uint16_t)bytes[th + 2] << 8) | bytes[th + 3];
                    bool eligible = sport == 8000 && dport == 9000 &&
                        bytes[th + 13] == KER_TCP_ACK && seq == active.status.receive_next &&
                        !payload && ack == active.status.send_next && active.status.send_bytes;
                    if (eligible && host_rto_stage == 1 && !host_ack_released) {
                        if (!host_ack_held) {
                            memcpy(host_held_ack, bytes, (size_t)n); host_held_ack_length = (size_t)n;
                            host_ack_held = true; host_release_ack_at = now + 800;
                        }
                        held = true;
                    } else if (eligible && host_rto_stage == 6 && !host_second_ack_released) {
                        if (!host_second_ack_held) {
                            memcpy(host_held_second_ack, bytes, (size_t)n); host_held_second_ack_length = (size_t)n;
                            host_second_ack_held = true; host_release_second_ack_at = now + 150;
                        }
                        held = true;
                    } else if (eligible && host_rto_stage == 3 && host_rto_retry_seen &&
                               ack == host_probe_sequence + host_probe_length) {
                        struct rte_mbuf *m = ker_packet_alloc(&pool); CHECK(m);
                        void *dst = rte_pktmbuf_append(m, (uint16_t)n); CHECK(dst);
                        memcpy(dst, bytes, (size_t)n); dispatch(m);
                        CHECK(!active.status.send_bytes && active.rto_ms >= host_probe_rto * 2);
                        host_karn_verified = true; host_rto_stage = 5; held = true;
                    }
                }
            }
no_rto_frame:
            if (!held) {
                struct rte_mbuf *m = ker_packet_alloc(&pool); CHECK(m);
                void *data = rte_pktmbuf_append(m, (uint16_t)n); CHECK(data);
                memcpy(data, bytes, (size_t)n); dispatch(m);
            }
        }
        CHECK(active.status.state != KER_TCP_ACTIVE_FAILED);
        if (active.status.state == KER_TCP_ACTIVE_READY && !reset) {
            if (total < 8192) {
                unsigned char data[512]; unsigned int length = 8192 - total;
                if (length > sizeof(data)) length = sizeof(data);
                if (host_rto_mode && (host_rto_stage == 0 || host_rto_stage == 2 || host_rto_stage == 5)) length = 1;
                if (host_rto_mode && host_rto_stage == 2) host_drop_next_data = true;
                for (unsigned int i = 0; i < length; ++i) data[i] = (total + i) % 251;
                int accepted = ker_tcp_active_write(&active, data, length);
                CHECK(accepted > 0 || accepted == -EAGAIN || accepted == -ENOSPC);
                if (accepted > 0) {
                    total += accepted;
                    if (host_rto_mode && host_rto_stage == 0) host_rto_stage = 1;
                    else if (host_rto_mode && host_rto_stage == 2) host_rto_stage = 3;
                    else if (host_rto_mode && host_rto_stage == 5) host_rto_stage = 6;
                }
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
    if (host_rto_mode) {
        if (!(host_ack_released && host_rto_dropped && host_rto_retry_seen &&
              host_karn_verified && host_second_ack_released && host_relearned))
            fprintf(stderr, "host RTO flags ack=%d drop=%d retry=%d karn=%d second=%d relearn=%d stage=%u rto=%llu\n",
                host_ack_released, host_rto_dropped, host_rto_retry_seen, host_karn_verified,
                host_second_ack_released, host_relearned, host_rto_stage, (unsigned long long)active.rto_ms);
        CHECK(host_ack_released && host_rto_dropped && host_rto_retry_seen &&
            host_karn_verified && host_second_ack_released && host_relearned);
    }
}
