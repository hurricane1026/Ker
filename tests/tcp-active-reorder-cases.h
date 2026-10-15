static unsigned char reorder_ring[1024];
static unsigned char reorder_map[128];
static unsigned char reorder_send[16];
static unsigned char host_hold[2048];

static void test_host(void)
{
    uint64_t deadline = now_ms() + 12000;
    unsigned int total = 0; bool held = false, exercised = false, reset = false;
    size_t held_len = 0, held_payload_len = 0; uint32_t held_seq = 0;
    while (now_ms() < deadline) {
        uint64_t now = now_ms();
        CHECK(ker_tcp_active_poll(&active, now) >= 0);
        int sent = ker_tx_export_poll(&tx, 8); CHECK(sent >= 0 || sent == -EAGAIN);
        unsigned char bytes[2048]; ssize_t n = read(tap, bytes, sizeof(bytes));
        if (n < 0) CHECK(errno == EAGAIN || errno == EINTR);
        if (n > 0) {
            size_t len = (size_t)n;
            if (len < 54 || bytes[12] != 8 || bytes[13] != 0) {
                struct rte_mbuf *m = ker_packet_alloc(&pool); CHECK(m);
                void *data = rte_pktmbuf_append(m, (uint16_t)len); CHECK(data);
                memcpy(data, bytes, len); dispatch(m); goto host_packet_done;
            }
            size_t ihl = (size_t)(bytes[14] & 15) * 4;
            CHECK(ihl >= 20 && 14 + ihl <= len && bytes[23] == 6);
            CHECK(be32(bytes + 26) == rte_be_to_cpu_32(peer_ip));
            CHECK(be32(bytes + 30) == rte_be_to_cpu_32(local_ip));
            size_t ip_total = ((size_t)bytes[16] << 8) | bytes[17];
            CHECK(ip_total >= ihl + 20 && ip_total <= len - 14);
            size_t tcp = 14 + ihl, hlen = (size_t)(bytes[tcp + 12] >> 4) * 4;
            CHECK(hlen >= 20 && ihl + hlen <= ip_total);
            CHECK(bytes[tcp] == (unsigned char)(rte_be_to_cpu_16(peer_port) >> 8));
            CHECK(bytes[tcp + 1] == (unsigned char)rte_be_to_cpu_16(peer_port));
            CHECK(bytes[tcp + 2] == (unsigned char)(rte_be_to_cpu_16(local_port) >> 8));
            CHECK(bytes[tcp + 3] == (unsigned char)rte_be_to_cpu_16(local_port));
            size_t payload_len = ip_total - ihl - hlen;
            uint32_t seq = be32(bytes + tcp + 4);
            if (!exercised && payload_len && !held) {
                CHECK(len <= sizeof(host_hold)); memcpy(host_hold, bytes, len);
                held_len = len; held_payload_len = payload_len; held_seq = seq; held = true; continue;
            }
            if (held && payload_len && seq == held_seq) continue;
            struct rte_mbuf *m = ker_packet_alloc(&pool); CHECK(m);
            void *data = rte_pktmbuf_append(m, (uint16_t)len); CHECK(data);
            memcpy(data, bytes, len); dispatch(m);
            if (held && payload_len && seq == held_seq + (uint32_t)held_payload_len) {
                CHECK(active.status.receive_next == held_seq);
                bool any = false; for (size_t i = 0; i < sizeof(reorder_map); ++i) any |= reorder_map[i] != 0;
                CHECK(any);
                m = ker_packet_alloc(&pool); CHECK(m);
                data = rte_pktmbuf_append(m, (uint16_t)held_len); CHECK(data);
                memcpy(data, host_hold, held_len); dispatch(m);
                CHECK(active.status.receive_next == seq + payload_len);
                for (size_t i = 0; i < sizeof(reorder_map); ++i) CHECK(reorder_map[i] == 0);
                held = false; exercised = true;
            }
host_packet_done:;
        }
        unsigned char out[257];
        if (active.status.state == KER_TCP_ACTIVE_READY)
            for (;;) {
                int got = ker_tcp_active_read(&active, out, sizeof(out));
                if (got == -EAGAIN || got == 0) break;
                CHECK(got > 0);
                for (int i = 0; i < got; ++i) CHECK(out[i] == total++ % 251);
            }
        if (exercised && total >= 4096 && !reset) {
            CHECK(ker_tcp_active_reset(&active) == 0); reset = true;
        }
        if (reset && !tx.packets) break;
        struct pollfd p = {.fd = tap, .events = POLLIN}; CHECK(poll(&p, 1, 1) >= 0 || errno == EINTR);
    }
    CHECK(exercised && total >= 4096 && reset);
}

static void reorder_ack(uint32_t ack, uint16_t window)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL; CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == KER_TCP_ACK && be32(tcp + 8) == ack);
    CHECK((((unsigned int)tcp[14] << 8) | tcp[15]) == window);
    ker_packet_free(frame);
}
static void reorder_reset_ack(uint32_t ack)
{
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *frame = NULL; CHECK(ker_tx_ring_take(&output, &frame) == 1);
    const unsigned char *tcp = rte_pktmbuf_mtod(frame, const unsigned char *) + 34;
    CHECK(tcp[13] == (KER_TCP_RST | KER_TCP_ACK) && be32(tcp + 8) == ack);
    ker_packet_free(frame);
}

static void test_active(void)
{
    drain(KER_TCP_SYN);
    CHECK(ker_tcp_active_reset(&active) == 0); drain(KER_TCP_RST);
    CHECK(ker_tcp_active_cleanup(&active) == 0);
    config.reorder_buffer_size = 1;
    CHECK(ker_tcp_active_start(&active, &receiver, &neighbors, peer_ip, &tx, &config, 100) == -EINVAL);
    CHECK(!active.receiver && !tx.active_refs);
    config.reorder_buffer_size = sizeof(reorder_map);
    start(101); drain(KER_TCP_SYN);
    inject(UINT32_MAX - 3U, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0);
    reorder_ack(UINT32_MAX - 2U, 16);
    CHECK(ker_tcp_active_write(&active, "send", 4) == 4);
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *sent = NULL; CHECK(ker_tx_ring_take(&output, &sent) == 1);
    const unsigned char *sent_tcp = rte_pktmbuf_mtod(sent, const unsigned char *) + 34;
    CHECK(be32(sent_tcp + 4) == 0 && sent_tcp[13] == (KER_TCP_ACK | KER_TCP_PSH));
    ker_packet_free(sent);
    const unsigned char first[] = {'a','b'}, future[] = {'e','f'};
    inject(UINT32_MAX - 2U, 0, KER_TCP_ACK, first, sizeof(first));
    reorder_ack(UINT32_MAX, 14);
    uint32_t saved_right = active.send_right;
    injected_window = 1;
    inject(1, 4, KER_TCP_ACK, future, sizeof(future));
    CHECK(active.status.receive_next == UINT32_MAX && active.status.receive_bytes == 2);
    CHECK(active.status.send_bytes == 4 && active.status.send_unacknowledged == 0);
    CHECK(active.send_right == saved_right && active.status.peer_window == 1024 && !active.status.local_fin);
    injected_window = 1024;
    CHECK((reorder_map[0] & 0x30) == 0x30);
    reorder_ack(UINT32_MAX, 14);
    const unsigned char conflict[] = {'X','Y'};
    inject(1, 4, KER_TCP_ACK, conflict, sizeof(conflict));
    CHECK(reorder_ring[4] == 'e' && reorder_ring[5] == 'f');
    reorder_ack(UINT32_MAX, 14);
    const unsigned char overlap[] = {'b','c','d'};
    inject(UINT32_MAX - 1U, 0, KER_TCP_ACK, overlap, sizeof(overlap));
    CHECK(active.status.receive_next == 3 && active.status.receive_bytes == 6);
    reorder_ack(3, 10);
    injected_window = 1;
    inject(3, 4, KER_TCP_ACK, NULL, 0);
    CHECK(active.status.send_bytes == 0 && active.status.send_unacknowledged == 4);
    CHECK(active.status.peer_window == 1 && active.send_right == 5);
    injected_window = 1024;
    unsigned char out[8] = {0};
    CHECK(ker_tcp_active_read(&active, out, sizeof(out)) == 6);
    CHECK(!memcmp(out, "abcdef", 6));
    CHECK(!reorder_map[0] && !reorder_map[1]);
    CHECK(ker_tcp_active_poll(&active, 102) == 1);
    reorder_ack(3, 16);
    CHECK(active.receive_right == 19);

    fill_tx(); fill_tx();
    uint32_t admitted_right = active.receive_right;
    const unsigned char wrapped_future[] = {'x','y'};
    inject(12, 4, KER_TCP_ACK, wrapped_future, sizeof(wrapped_future));
    CHECK(active.status.last_tx_error == -ENOSPC && active.status.ack_pending);
    CHECK(active.receive_right == admitted_right && (reorder_map[0] & 1) && (reorder_map[1] & 0x80));
    drain(KER_TCP_SYN | KER_TCP_ACK); drain(KER_TCP_SYN | KER_TCP_ACK);
    CHECK(ker_tcp_active_poll(&active, 103) == 1);
    reorder_ack(3, 16); CHECK(active.receive_right == 19);
    const unsigned char wrapped_gap[] = "ghijklmno";
    inject(3, 4, KER_TCP_ACK, wrapped_gap, 9);
    CHECK(active.status.receive_next == 14 && active.status.receive_bytes == 11);
    CHECK(!reorder_map[0] && !reorder_map[1]);
    reorder_ack(14, 5);
    CHECK(ker_tcp_active_read(&active, out, sizeof(out)) == 8);
    unsigned char tail_out[8]; CHECK(ker_tcp_active_read(&active, tail_out, sizeof(tail_out)) == 3);
    CHECK(!memcmp(out, "ghijklmn", 8) && !memcmp(tail_out, "oxy", 3));
    CHECK(ker_tcp_active_poll(&active, 104) == 1); reorder_ack(14, 16);

    injected_window = 8;
    const unsigned char unread = 'z';
    inject(14, 4, KER_TCP_ACK, &unread, 1);
    reorder_ack(15, 15);
    CHECK(active.status.peer_window == 8 && active.send_right == 12);
    CHECK(ker_tcp_active_shutdown_write(&active) == 0);
    uint64_t close_deadline = active.close_deadline_ms;
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    struct rte_mbuf *local_fin = NULL; CHECK(ker_tx_ring_take(&output, &local_fin) == 1);
    const unsigned char *local_fin_tcp = rte_pktmbuf_mtod(local_fin, const unsigned char *) + 34;
    CHECK(local_fin_tcp[13] == (KER_TCP_FIN | KER_TCP_ACK) && be32(local_fin_tcp + 4) == 4);
    ker_packet_free(local_fin);
    const unsigned char tail[] = {'q','r'};
    injected_window = 1;
    inject(17, 5, KER_TCP_ACK | KER_TCP_FIN, tail, sizeof(tail));
    CHECK(active.reorder_fin_pending && !active.status.local_fin_acked);
    CHECK(active.status.state == KER_TCP_ACTIVE_FIN_WAIT_1 && active.status.send_unacknowledged == 4);
    CHECK(active.status.peer_window == 8 && active.send_right == 12 && active.close_deadline_ms == close_deadline);
    reorder_ack(15, 15);
    injected_window = 8;
    inject(15, 5, KER_TCP_ACK, NULL, 0);
    CHECK(active.status.local_fin_acked && active.status.send_unacknowledged == 5);
    CHECK(active.status.state == KER_TCP_ACTIVE_FIN_WAIT_2 && active.reorder_fin_pending);
    CHECK(active.status.receive_bytes == 1 && active.status.receive_next == 15);
    CHECK(active.close_deadline_ms == close_deadline);
    injected_window = 1024;

    CHECK(ker_tcp_active_poll(&active, close_deadline) == 1);
    CHECK(active.status.state == KER_TCP_ACTIVE_FAILED && active.status.error == -ETIMEDOUT);
    CHECK(!active.status.receive_bytes && !reorder_map[0] && !reorder_map[1]);
    CHECK(!active.reorder_fin_pending && !active.status.send_bytes);
    CHECK(ker_tcp_active_cleanup(&active) == 0);

    start(200); drain(KER_TCP_SYN);
    inject(UINT32_MAX - 3U, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0);
    reorder_ack(UINT32_MAX - 2U, 16);
    const unsigned char future_gap[] = {'i','j'};
    inject(1, 0, KER_TCP_ACK, future_gap, sizeof(future_gap));
    CHECK(reorder_map[0] || reorder_map[1]);
    reorder_ack(UINT32_MAX - 2U, 16);
    CHECK(ker_tcp_active_reset(&active) == 0);
    CHECK(!reorder_map[0] && !reorder_map[1]);
    reorder_reset_ack(UINT32_MAX - 2U);
    CHECK(ker_tcp_active_cleanup(&active) == 0);

    config.reorder_buffer = NULL; config.reorder_buffer_size = 0;
    start(300); drain(KER_TCP_SYN);
    inject(UINT32_MAX - 3U, 0, KER_TCP_SYN | KER_TCP_ACK, NULL, 0);
    reorder_ack(UINT32_MAX - 2U, 16);
    const unsigned char default_gap[] = {'i','j'};
    inject(1, 0, KER_TCP_ACK, default_gap, sizeof(default_gap));
    CHECK(active.status.receive_next == UINT32_MAX - 2U && active.status.receive_bytes == 0);
    reorder_ack(UINT32_MAX - 2U, 16);
    CHECK(ker_tcp_active_reset(&active) == 0); reorder_reset_ack(UINT32_MAX - 2U);
}
