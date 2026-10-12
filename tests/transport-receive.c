#include "check.h"
#include "eal.h"
#include "runtime/transport-receive.h"
#include "runtime/ethernet.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include <errno.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_transport_receiver receiver;
static struct ker_worker worker;
static struct rte_mbuf *pending;
static unsigned int callbacks;
static int unregister_result;
static int dispatch_status;
static enum ker_transport_protocol expected_protocol = KER_TRANSPORT_UDP;
static int callback_status = NET_RX_SUCCESS;
static int expected_dispatch_error;
static unsigned int expected_handlers = 1;
static int expected_status = NET_RX_SUCCESS;
static unsigned char expected_echo_type = 8;
static const unsigned char mac[ETH_ALEN] = {2, 0x11, 0x22, 0x33, 0x44, 0x55};

static uint16_t checksum(const unsigned char *p, unsigned int n)
{
    uint32_t sum = 0;
    for (unsigned int i = 0; i < n; i += 2) {
        sum += (uint16_t)p[i] << 8;
        if (i + 1 < n) sum += p[i + 1];
    }
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static void make_frame(unsigned char frame[57], unsigned char protocol, bool valid_checksum)
{
    memset(frame, 0, 57);
    memcpy(frame, mac, 6); memcpy(frame + 6, mac, 6);
    frame[12] = 0x08; frame[13] = 0x00;
    unsigned char *ip = frame + ETH_HLEN;
    ip[0] = 0x45; ip[2] = 0; ip[3] = protocol == 6 ? 43 : 31; ip[8] = 64; ip[9] = protocol;
    ip[12] = 192; ip[13] = 0; ip[14] = 2; ip[15] = 1;
    ip[16] = 198; ip[17] = 51; ip[18] = 100; ip[19] = 2;
    uint16_t sum = checksum(ip, 20); ip[10] = (unsigned char)(sum >> 8); ip[11] = (unsigned char)sum;
    if (protocol == 6) {
        unsigned char *tcp = ip + 20;
        tcp[0] = 0x12; tcp[1] = 0x34; tcp[2] = 0x56; tcp[3] = 0x78;
        tcp[12] = 0x50; tcp[13] = 0x10; tcp[20] = 0xaa; tcp[21] = 0xbb; tcp[22] = 0xcc;
        if (valid_checksum) {
            unsigned char pseudo[12] = {192,0,2,1,198,51,100,2,0,6,0,23}; uint32_t total = 0;
            for (unsigned int i = 0; i < 12; i += 2) total += ((uint16_t)pseudo[i] << 8) | pseudo[i + 1];
            for (unsigned int i = 0; i < 23; i += 2)
                total += ((uint16_t)tcp[i] << 8) | (i + 1 < 23 ? tcp[i + 1] : 0);
            while (total >> 16) total = (total & 0xffff) + (total >> 16);
            uint16_t csum = (uint16_t)~total; tcp[16] = (unsigned char)(csum >> 8); tcp[17] = (unsigned char)csum;
        } else { tcp[16] = 0x45; tcp[17] = 0x67; }
        return;
    }
    if (protocol == 1) {
        unsigned char *icmp = ip + 20;
        icmp[0] = expected_echo_type; icmp[1] = 0;
        icmp[4] = 0x12; icmp[5] = 0x34; icmp[6] = 0x56; icmp[7] = 0x78;
        icmp[8] = 0xaa; icmp[9] = 0xbb; icmp[10] = 0xcc;
        if (valid_checksum) {
            uint16_t csum = checksum(icmp, 11);
            icmp[2] = (unsigned char)(csum >> 8); icmp[3] = (unsigned char)csum;
        } else { icmp[2] = 0x45; icmp[3] = 0x67; }
        return;
    }
    if (protocol != 17) return;
    unsigned char *udp = ip + 20;
    udp[0] = 0x12; udp[1] = 0x34; udp[2] = 0x56; udp[3] = 0x78;
    udp[4] = 0; udp[5] = 11;
    udp[8] = 0xaa; udp[9] = 0xbb; udp[10] = 0xcc;
    if (valid_checksum) {
        unsigned char pseudo[12] = {192,0,2,1,198,51,100,2,0,17,0,11};
        uint32_t total = 0;
        for (unsigned int i = 0; i < 12; i += 2) total += ((uint16_t)pseudo[i] << 8) | pseudo[i + 1];
        for (unsigned int i = 0; i < 11; i += 2) total += ((uint16_t)udp[i] << 8) | (i + 1 < 11 ? udp[i + 1] : 0);
        while (total >> 16) total = (total & 0xffff) + (total >> 16);
        uint16_t usum = (uint16_t)~total;
        if (!usum) usum = 0xffff;
        udp[6] = (unsigned char)(usum >> 8); udp[7] = (unsigned char)usum;
    } else {
        udp[6] = 0x45; udp[7] = 0x67;
    }
}

static int message(const struct ker_transport_message *m, void *arg)
{
    CHECK(arg == &receiver && worker.polling && !worker.timers.polling);
    CHECK(m->protocol == expected_protocol && m->ipv4.packet_length >= 23);
    if (m->protocol == KER_TRANSPORT_ICMP_ECHO) {
        CHECK(m->packet.icmp_echo.type == expected_echo_type && m->packet.icmp_echo.code == 0);
        CHECK(m->packet.icmp_echo.identifier == rte_cpu_to_be_16(0x1234));
        CHECK(m->packet.icmp_echo.sequence == rte_cpu_to_be_16(0x5678));
        CHECK(m->packet.icmp_echo.payload_length == 3 && m->packet.icmp_echo.payload[0] == 0xaa &&
            m->packet.icmp_echo.payload[2] == 0xcc);
    } else if (m->protocol == KER_TRANSPORT_UDP) {
        CHECK(m->packet.udp.source_port == rte_cpu_to_be_16(0x1234));
        CHECK(m->packet.udp.destination_port == rte_cpu_to_be_16(0x5678));
        CHECK(m->packet.udp.payload_length == 3 && m->packet.udp.payload[0] == 0xaa && m->packet.udp.payload[2] == 0xcc);
    } else {
        CHECK(m->packet.tcp.source_port == rte_cpu_to_be_16(0x1234));
        CHECK(m->packet.tcp.destination_port == rte_cpu_to_be_16(0x5678));
        CHECK(m->packet.tcp.payload_length == 3 && m->packet.tcp.payload[0] == 0xaa && m->packet.tcp.payload[2] == 0xcc);
    }
    ++callbacks;
    unregister_result = ker_transport_receiver_unregister(&receiver);
    CHECK(unregister_result == -EBUSY);
    CHECK(ker_receive_runtime_cleanup(&runtime) == -EBUSY);
    CHECK(ker_eth_device_cleanup(&device) == -EBUSY);
    return callback_status;
}

static int rx(void *arg, unsigned int budget)
{
    (void)arg;
    CHECK(budget == 1);
    if (!pending) return 0;
    struct rte_mbuf *source = pending; pending = NULL;
    struct sk_buff *skb = NULL;
    int copied = ker_eth_receive_copy_chain(&device, source, 128, &skb);
    ker_packet_free(source);
    CHECK(copied == 0 && skb);
    struct ker_receive_result result = {0};
    dispatch_status = ker_receive_dispatch(&runtime, &device, &skb, &result);
    CHECK(dispatch_status == expected_dispatch_error && !skb);
    CHECK(result.handlers == expected_handlers);
    CHECK(result.status == expected_status);
    return 1;
}

static struct rte_mbuf *make_chain(const unsigned char frame[57])
{
    const uint16_t lengths[] = {13, 2, 8, 3, 1, 7, 23};
    struct rte_mbuf *segments[7];
    unsigned int offset = 0;
    for (unsigned int i = 0; i < 7; ++i) {
        segments[i] = ker_packet_alloc(&pool); CHECK(segments[i]);
        unsigned char *data = (unsigned char *)rte_pktmbuf_append(segments[i], lengths[i]); CHECK(data);
        memcpy(data, frame + offset, lengths[i]); offset += lengths[i];
    }
    for (int i = 5; i >= 0; --i) CHECK(rte_pktmbuf_chain(segments[i], segments[i + 1]) == 0);
    CHECK(offset == 57 && segments[0]->nb_segs == 7 && segments[0]->pkt_len == 57);
    return segments[0];
}

static void poll_frame(const unsigned char frame[57])
{
    pending = make_chain(frame);
    struct ker_worker_result result = {0};
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &result) == 0);
    CHECK(result.rx == 1 && pending == NULL && context.live == 0);
}

static int observe_shared(struct sk_buff *skb, struct ker_protocol_handler *handler,
    struct net_device *original, void *arg)
{
    (void)handler; (void)original; (void)arg;
    CHECK(ker_skb_free(skb) == 0);
    return NET_RX_SUCCESS;
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "transport_rx", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "transport_rx_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "transport0", 1, mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device, message, &receiver) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .rx_budget = 1};
    struct ker_worker_ops ops = {.rx = rx};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);

    unsigned char frame[57];
    make_frame(frame, 17, true); poll_frame(frame);
    CHECK(callbacks == 1 && receiver.validation_error == 0);
    expected_status = NET_RX_DROP;
    make_frame(frame, 17, false); poll_frame(frame);
    CHECK(callbacks == 1 && receiver.validation_error == -EBADMSG);
    make_frame(frame, 132, true); poll_frame(frame);
    CHECK(callbacks == 1 && receiver.validation_error == -EPROTONOSUPPORT);
    make_frame(frame, 17, true); frame[ETH_HLEN + 10] ^= 1; poll_frame(frame);
    CHECK(callbacks == 1 && receiver.validation_error == -EBADMSG);
    make_frame(frame, 17, true);
    frame[ETH_HLEN + 6] = 0x20; /* MF requires reassembly, outside this adapter. */
    frame[ETH_HLEN + 10] = frame[ETH_HLEN + 11] = 0;
    uint16_t repaired = checksum(frame + ETH_HLEN, 20);
    frame[ETH_HLEN + 10] = (unsigned char)(repaired >> 8);
    frame[ETH_HLEN + 11] = (unsigned char)repaired;
    poll_frame(frame);
    CHECK(callbacks == 1 && receiver.validation_error == -ENOTSUP);
    expected_status = NET_RX_SUCCESS;
    expected_protocol = KER_TRANSPORT_TCP;
    make_frame(frame, 6, true); poll_frame(frame);
    CHECK(callbacks == 2 && receiver.validation_error == 0);
    expected_status = NET_RX_DROP;
    make_frame(frame, 6, false); poll_frame(frame);
    CHECK(callbacks == 2 && receiver.validation_error == -EBADMSG);
    expected_protocol = KER_TRANSPORT_ICMP_ECHO;
    expected_status = NET_RX_SUCCESS;
    make_frame(frame, 1, true); poll_frame(frame);
    CHECK(callbacks == 3 && receiver.validation_error == 0);
    expected_echo_type = 0;
    make_frame(frame, 1, true); poll_frame(frame);
    CHECK(callbacks == 4 && receiver.validation_error == 0);
    expected_status = NET_RX_DROP;
    expected_echo_type = 8;
    make_frame(frame, 1, true); frame[ETH_HLEN + 20] = 3; poll_frame(frame);
    CHECK(callbacks == 4 && receiver.validation_error == -ENOTSUP);
    make_frame(frame, 1, true);
    frame[ETH_HLEN + 6] = 0x20; /* ICMP fragments are not reassembled. */
    frame[ETH_HLEN + 10] = frame[ETH_HLEN + 11] = 0;
    repaired = checksum(frame + ETH_HLEN, 20);
    frame[ETH_HLEN + 10] = (unsigned char)(repaired >> 8);
    frame[ETH_HLEN + 11] = (unsigned char)repaired;
    poll_frame(frame);
    CHECK(callbacks == 4 && receiver.validation_error == -ENOTSUP);
    make_frame(frame, 1, true);
    frame[ETH_HLEN + 7] = 1; /* Nonzero fragment offset also requires reassembly. */
    frame[ETH_HLEN + 10] = frame[ETH_HLEN + 11] = 0;
    repaired = checksum(frame + ETH_HLEN, 20);
    frame[ETH_HLEN + 10] = (unsigned char)(repaired >> 8);
    frame[ETH_HLEN + 11] = (unsigned char)repaired;
    poll_frame(frame);
    CHECK(callbacks == 4 && receiver.validation_error == -ENOTSUP);
    expected_status = NET_RX_DROP;
    make_frame(frame, 1, false); poll_frame(frame);
    CHECK(callbacks == 4 && receiver.validation_error == -EBADMSG);
    make_frame(frame, 1, true); frame[ETH_HLEN + 20 + 1] = 1; poll_frame(frame);
    CHECK(callbacks == 4 && receiver.validation_error == -EINVAL);
    make_frame(frame, 1, true);
    frame[ETH_HLEN + 3] = 27; /* Seven ICMP bytes despite trailing Ethernet padding. */
    frame[ETH_HLEN + 10] = frame[ETH_HLEN + 11] = 0;
    repaired = checksum(frame + ETH_HLEN, 20);
    frame[ETH_HLEN + 10] = (unsigned char)(repaired >> 8);
    frame[ETH_HLEN + 11] = (unsigned char)repaired;
    poll_frame(frame);
    CHECK(callbacks == 4 && receiver.validation_error == -EMSGSIZE);
    expected_status = NET_RX_SUCCESS;
    make_frame(frame, 1, true);
    callback_status = NET_RX_DROP; expected_status = NET_RX_DROP;
    poll_frame(frame);
    CHECK(callbacks == 5 && receiver.validation_error == 0);
    callback_status = -EINVAL; expected_dispatch_error = -EPROTO;
    poll_frame(frame);
    CHECK(callbacks == 6 && receiver.validation_error == 0);
    callback_status = NET_RX_SUCCESS; expected_dispatch_error = 0; expected_status = NET_RX_SUCCESS;
    callback_status = NET_RX_DROP;
    expected_status = NET_RX_DROP;
    make_frame(frame, 17, true); expected_protocol = KER_TRANSPORT_UDP; poll_frame(frame);
    CHECK(callbacks == 7);
    callback_status = -EINVAL; expected_dispatch_error = -EPROTO;
    poll_frame(frame);
    CHECK(callbacks == 8);
    callback_status = NET_RX_SUCCESS; expected_dispatch_error = 0; expected_status = NET_RX_SUCCESS;

    /* A second matching handler makes the earlier callback see a shared skb.
     * The immutable view rejects it, and the later owner still releases it. */
    struct ker_protocol_handler observer = {0};
    CHECK(ker_transport_receiver_unregister(&receiver) == 0);
    CHECK(ker_protocol_register(&runtime, &observer, &device, rte_cpu_to_be_16(ETH_P_IP),
        observe_shared, NULL) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device, message, &receiver) == 0);
    unsigned int before_fanout = callbacks;
    expected_handlers = 2;
    poll_frame(frame);
    CHECK(callbacks == before_fanout && receiver.validation_error == -EBUSY);
    expected_protocol = KER_TRANSPORT_ICMP_ECHO; expected_echo_type = 8;
    make_frame(frame, 1, true);
    poll_frame(frame);
    CHECK(callbacks == before_fanout && receiver.validation_error == -EBUSY);
    CHECK(ker_protocol_unregister(&observer) == 0);
    expected_handlers = 1; expected_status = NET_RX_SUCCESS;

    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_transport_receiver_unregister(&receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("Transport receiver worker dispatch and ownership passed");
    return 0;
}
