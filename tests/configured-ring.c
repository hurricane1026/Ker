#include "check.h"
#include "eal.h"
#include "runtime/arp-receive.h"
#include "runtime/arp.h"
#include "runtime/ethernet.h"
#include "runtime/icmp-echo-create.h"
#include "runtime/ipv4-address.h"
#include "runtime/memory.h"
#include "runtime/receive.h"
#include "runtime/rx-ring.h"
#include "runtime/tcp-create.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"
#include "runtime/tx-ring.h"
#include "runtime/udp-create.h"
#include "runtime/worker.h"
#include <errno.h>
#include <limits.h>
#include <net/checksum.h>

#define POOL_SIZE 127U
#define FRAME_MAX (ETH_HLEN + 60U + 60U + sizeof(data_template))
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static struct ker_tx_ring ring;
static struct ker_tx_export normal_tx, exact_tx;
static struct ker_rx_ring rx;
static struct ker_receive_runtime runtime;
static struct ker_arp_receiver arp_receiver;
static struct ker_transport_receiver ip_receiver;
static struct ker_worker worker;
static const uint8_t smac[6] = {2, 0x10, 0x11, 0x12, 0x13, 0x14};
static const uint8_t dmac[6] = {2, 0x20, 0x21, 0x22, 0x23, 0x24};
static const uint8_t bcast[6] = {255, 255, 255, 255, 255, 255};
static const uint8_t zero_mac[6] = {0};
static const __be32 sip = (__be32)0x010200c0, dip = (__be32)0x026433c6;
static const __be16 sport = (__be16)0x3412, dport = (__be16)0x7856;
static unsigned int expected_protocol, expected_marker, ip_received,
    arp_received;
static bool force_rx_pressure;
static bool force_sink_backpressure;
static const unsigned char data_template[9] = {0x91, 0x22, 0x33, 0x44, 0x55,
                                               0x66, 0x77, 0x88, 0x99};

static uint16_t checksum(const uint8_t *p, size_t n) {
  uint32_t sum = 0;
  for (size_t i = 0; i < n; i += 2)
    sum += ((uint16_t)p[i] << 8) | (i + 1 < n ? p[i + 1] : 0);
  while (sum >> 16)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (uint16_t)~sum;
}
static int sink(struct rte_mbuf *chain, void *arg) {
  if (force_sink_backpressure) {
    force_sink_backpressure = false;
    return -EAGAIN;
  }
  return ker_tx_ring_sink(chain, arg);
}
static struct sk_buff *make_ip(unsigned int proto, uint8_t marker) {
  uint8_t data[sizeof(data_template)];
  memcpy(data, data_template, sizeof(data));
  data[0] = marker;
  const struct ker_ipv4_header_fields fields = {0};
  struct sk_buff *skb = NULL;
  if (proto == IPPROTO_UDP) {
    CHECK(ker_udp_ipv4_create_configured_fields(&address, dmac, dip, sport,
                                                dport, 64, &fields, NULL, 0,
                                                data, sizeof(data), &skb) == 0);
  } else if (proto == IPPROTO_TCP) {
    CHECK(ker_tcp_ipv4_create_configured_fields(
              &address, dmac, dip, sport, dport, rte_cpu_to_be_32(0x10203040),
              rte_cpu_to_be_32(0x50607080), rte_cpu_to_be_16(4096), 0x18, 64,
              &fields, NULL, 0, NULL, 0, data, sizeof(data), &skb) == 0);
    unsigned int start = ETH_HLEN + 20, length = skb->len - start;
    __wsum pseudo = csum_tcpudp_nofold(sip, dip, length, IPPROTO_TCP, 0);
    __sum16 seed = (__sum16)~csum_fold(pseudo);
    memcpy(skb->data + start + 16, &seed, sizeof(seed));
    skb->ip_summed = CHECKSUM_PARTIAL;
    skb->csum_start = (uint16_t)(skb_headroom(skb) + start);
    skb->csum_offset = 16;
  } else {
    CHECK(proto == IPPROTO_ICMP);
    CHECK(ker_icmp_echo_ipv4_create_configured_fields(
              &address, dmac, dip, rte_cpu_to_be_16(0x1234),
              rte_cpu_to_be_16(0x5678), 8, 64, &fields, NULL, 0, data,
              sizeof(data), &skb) == 0);
    unsigned int start = ETH_HLEN + 20;
    const __be16 zero = 0;
    memcpy(skb->data + start + 2, &zero, sizeof(zero));
    skb->ip_summed = CHECKSUM_PARTIAL;
    skb->csum_start = (uint16_t)(skb_headroom(skb) + start);
    skb->csum_offset = 2;
  }
  CHECK(skb->len <= FRAME_MAX && !memcmp(skb->data, dmac, ETH_ALEN) &&
        !memcmp(skb->data + ETH_ALEN, smac, ETH_ALEN) &&
        !memcmp(skb->data + ETH_HLEN + 12, &sip, sizeof(sip)) &&
        !memcmp(skb->data + ETH_HLEN + 16, &dip, sizeof(dip)));
  return skb;
}
static struct ker_tx_export *tx_for(unsigned int proto) {
  return proto == IPPROTO_ICMP ? &exact_tx : &normal_tx;
}
static int tx_poll(void *unused, unsigned int budget) {
  (void)unused;
  int n = ker_tx_export_poll(&normal_tx, budget);
  if (n < 0)
    return n;
  int e = ker_tx_export_poll(&exact_tx, budget - (unsigned int)n);
  return e < 0 ? e : n + e;
}
static int rx_poll(void *arg, unsigned int budget) {
  struct rte_mbuf *pressure = NULL;
  if (force_rx_pressure) {
    pressure = ker_packet_alloc(&pool);
    CHECK(pressure && rte_mempool_avail_count(pool.mbufs) == 0);
  }
  int result = ker_rx_ring_poll(arg, budget);
  if (pressure)
    ker_packet_free(pressure);
  force_rx_pressure = false;
  return result;
}
static int receive_ip(const struct ker_transport_message *m, void *arg) {
  CHECK(arg == &ip_receiver && m->protocol == expected_protocol);
  const uint8_t *p = NULL;
  size_t n = 0;
  if (m->protocol == KER_TRANSPORT_UDP) {
    p = m->packet.udp.payload;
    n = m->packet.udp.payload_length;
  } else if (m->protocol == KER_TRANSPORT_TCP) {
    p = m->packet.tcp.payload;
    n = m->packet.tcp.payload_length;
  } else {
    p = m->packet.icmp_echo.payload;
    n = m->packet.icmp_echo.payload_length;
  }
  uint8_t expected[sizeof(data_template)];
  memcpy(expected, data_template, sizeof(expected));
  expected[0] = (uint8_t)expected_marker;
  CHECK(n == sizeof(expected) && !memcmp(p, expected, n));
  ++ip_received;
  return NET_RX_SUCCESS;
}
static int receive_arp(const struct ker_arp_message *m, void *arg) {
  CHECK(arg == &arp_receiver && m->operation == ARPOP_REQUEST &&
        m->sender_ip == sip && m->target_ip == rte_cpu_to_be_32(0xc6336403) &&
        !m->target_local && !memcmp(m->sender_mac, smac, 6) &&
        !memcmp(m->target_mac, zero_mac, 6));
  ++arp_received;
  return NET_RX_SUCCESS;
}
static void poll_worker(void) {
  struct ker_worker_result progress = {0};
  CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
}
static void send_ip(unsigned int proto, uint8_t marker) {
  expected_protocol = proto;
  expected_marker = marker;
  unsigned int before = ip_received;
  struct sk_buff *skb = make_ip(proto, marker);
  struct ker_tx_export *tx = tx_for(proto);
  struct sk_buff *original = skb;
  uint8_t snapshot[FRAME_MAX];
  unsigned int original_length = skb->len;
  memcpy(snapshot, skb->data, original_length);
  uint8_t checksum_state = skb->ip_summed;
  uint16_t checksum_start = skb->csum_start, checksum_offset = skb->csum_offset;
  unsigned int previous_rx_completed = rx.last_completed;
  CHECK(ker_tx_export_enqueue(tx, &skb) == 0 && !skb);
  unsigned int available_before = rte_mempool_avail_count(pool.mbufs);
  force_sink_backpressure = true;
  struct ker_worker_result progress = {0};
  int blocked = ker_worker_poll(&worker, worker.timers.now_ns, &progress);
  CHECK(blocked == -EAGAIN);
  CHECK(tx->pending == original && tx->last_error == -EAGAIN);
  CHECK(rx.last_completed == previous_rx_completed);
  CHECK(original->len == original_length &&
        !memcmp(original->data, snapshot, original_length) &&
        original->ip_summed == checksum_state &&
        original->csum_start == checksum_start &&
        original->csum_offset == checksum_offset &&
        rte_mempool_avail_count(pool.mbufs) == available_before);
  poll_worker();
  CHECK(ip_received == before + 1 && rx.last_dropped == 0 &&
        rx.last_error == 0);
}
static void export_pair(unsigned int proto, uint8_t first_marker,
                        uint8_t second_marker,
                        uint8_t expected_first[FRAME_MAX],
                        unsigned int *first_len) {
  expected_protocol = proto;
  expected_marker = second_marker;
  struct sk_buff *first = make_ip(proto, first_marker),
                 *second = make_ip(proto, second_marker);
  struct rte_mbuf *oracle = NULL;
  int error =
      proto == IPPROTO_ICMP
          ? ker_skb_to_mbuf_chain_software_checksum_exact(first, 13, &oracle)
          : (proto == IPPROTO_TCP
                 ? ker_skb_to_mbuf_chain_software_checksum(first, 13, &oracle)
                 : ker_skb_to_mbuf_chain_copy(first, 13, &oracle));
  CHECK(error == 0 && oracle && oracle->pkt_len <= FRAME_MAX);
  *first_len = oracle->pkt_len;
  const void *wire = rte_pktmbuf_read(oracle, 0, *first_len, expected_first);
  CHECK(wire && wire == expected_first);
  ker_packet_free(oracle);
  struct ker_tx_export *tx = tx_for(proto);
  CHECK(ker_tx_export_enqueue(tx, &first) == 0 && !first);
  CHECK(ker_tx_export_enqueue(tx, &second) == 0 && !second);
  CHECK(ker_tx_export_poll(tx, 2) == 2 && rte_ring_count(ring.ring) == 2);
}
static void compare_chain(struct rte_mbuf *chain, const uint8_t *expected,
                          unsigned int length) {
  uint8_t bytes[FRAME_MAX];
  CHECK(chain && chain->pkt_len == length && length <= sizeof(bytes));
  const void *read = rte_pktmbuf_read(chain, 0, length, bytes);
  CHECK(read &&
        (read == bytes ||
         read == (const void *)rte_pktmbuf_mtod(chain, const void *)) &&
        !memcmp(read, expected, length));
  CHECK(chain->nb_segs > 1);
  unsigned int segs = 0;
  size_t total = 0;
  for (struct rte_mbuf *p = chain; p; p = p->next) {
    CHECK(rte_mbuf_refcnt_read(p) == 1);
    ++segs;
    total += p->data_len;
  }
  CHECK(segs == chain->nb_segs && total == length);
}
static void pressure_cancel(unsigned int proto, uint8_t first, uint8_t later) {
  uint8_t expected[FRAME_MAX];
  unsigned int length = 0;
  export_pair(proto, first, later, expected, &length);
  struct rte_mbuf *held[POOL_SIZE];
  unsigned int n = 0;
  while (n < POOL_SIZE && rte_mempool_avail_count(pool.mbufs) > 1 &&
         (held[n] = ker_packet_alloc(&pool)) != NULL)
    ++n;
  CHECK(n > 0 && rte_mempool_avail_count(pool.mbufs) == 1);
  force_rx_pressure = true;
  int rc = ker_worker_poll(&worker, worker.timers.now_ns,
                           &(struct ker_worker_result){0});
  CHECK(rc == -ENOMEM && rx.pending && rte_ring_count(ring.ring) == 1 &&
        rx.last_error == -ENOMEM && rx.last_completed == 0 &&
        rx.last_dropped == 0);
  struct rte_mbuf *cancelled = NULL;
  CHECK(ker_rx_ring_cancel(&rx, &cancelled) == 1 && cancelled && !rx.pending &&
        rte_ring_count(ring.ring) == 1);
  compare_chain(cancelled, expected, length);
  ker_packet_free(cancelled);
  while (n)
    ker_packet_free(held[--n]);
  expected_protocol = proto;
  expected_marker = later;
  unsigned int old = ip_received;
  poll_worker();
  CHECK(ip_received == old + 1 && rte_ring_empty(ring.ring) &&
        rx.last_error == 0);
}
static void drop_bad_ip(unsigned int corruption) {
  struct sk_buff *skb = make_ip(IPPROTO_UDP, (uint8_t)(0xd0 + corruption));
  uint8_t *ip = skb->data + ETH_HLEN;
  if (corruption == 0)
    ip[10] ^= 1; /* bad IPv4 checksum */
  else if (corruption == 1)
    ip[20 + 6] ^= 1; /* bad UDP checksum */
  else if (corruption == 2 || corruption == 3) {
    /* MF and a nonzero fragment offset are rejected by the UDP view. */
    ip[6] = corruption == 2 ? 0x20 : 0;
    ip[7] = corruption == 2 ? 0 : 1;
    ip[10] = ip[11] = 0;
    uint16_t sum = checksum(ip, 20);
    __be16 wire = rte_cpu_to_be_16(sum);
    memcpy(ip + 10, &wire, 2);
  } else {
    ip[9] = 132;
    ip[10] = ip[11] = 0;
    uint16_t sum = checksum(ip, 20);
    __be16 wire = rte_cpu_to_be_16(sum);
    memcpy(ip + 10, &wire, 2);
  }
  struct ker_tx_export *tx = &normal_tx;
  CHECK(ker_tx_export_enqueue(tx, &skb) == 0 && !skb);
  unsigned int before = ip_received;
  poll_worker();
  CHECK(ip_received == before && rx.last_dropped == 1 &&
        rx.last_completed == 1);
}

int main(void) {
  ker_test_eal_init();
  CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
  CHECK(ker_packet_pool_init(&pool, "cfg_ring", POOL_SIZE, 0, 4096,
                             SOCKET_ID_ANY) == 0);
  CHECK(ker_skb_context_init(&context, &pool, "cfg_ring_skb") == 0);
  CHECK(ker_eth_device_init(&device, &context, "cfg-ring", 51, smac) == 0);
  CHECK(ker_arp_device_setup(&device) == 0);
  CHECK(ker_ipv4_address_init(&address, &device, sip, 24) == 0);
  CHECK(ker_tx_ring_init(&ring, "cfg_ring1", 4, SOCKET_ID_ANY) == 0);
  CHECK(ker_tx_export_init_chain_software_checksum(
            &normal_tx, &context, 8, 32768, 13, sink, &ring) == 0);
  CHECK(ker_tx_export_init_chain_software_checksum_exact(
            &exact_tx, &context, 8, 32768, 13, sink, &ring) == 0);
  CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
  CHECK(ker_arp_receiver_register(&arp_receiver, &runtime, &address,
                                  receive_arp, &arp_receiver) == 0);
  CHECK(ker_transport_receiver_register(&ip_receiver, &runtime, &device,
                                        receive_ip, &ip_receiver) == 0);
  CHECK(device.protocol_live == 2 &&
        ker_eth_device_cleanup(&device) == -EBUSY &&
        ker_ipv4_address_cleanup(&address) == -EBUSY);
  CHECK(ker_rx_ring_init(&rx, &ring, &device, &runtime, 128) == 0);
  struct ker_worker_config cfg = {
      .timer_budget = 1, .tx_budget = 8, .rx_budget = 8};
  struct ker_worker_ops ops = {.tx = tx_poll, .rx = rx_poll, .arg = &rx};
  CHECK(ker_worker_init(&worker, &pool, &cfg, &ops) == 0);
  send_ip(IPPROTO_UDP, 0xa1);
  send_ip(IPPROTO_TCP, 0xa2);
  send_ip(IPPROTO_ICMP, 0xa3);
  struct sk_buff *arp = NULL;
  CHECK(ker_arp_create_configured(&address, ARPOP_REQUEST,
                                  rte_cpu_to_be_32(0xc6336403), bcast, zero_mac,
                                  &arp) == 0);
  CHECK(ker_tx_export_enqueue(&normal_tx, &arp) == 0 && !arp);
  poll_worker();
  CHECK(arp_received == 1);
  drop_bad_ip(0);
  drop_bad_ip(1);
  drop_bad_ip(2);
  drop_bad_ip(3);
  drop_bad_ip(4);
  pressure_cancel(IPPROTO_UDP, 0xb1, 0xb2);
  pressure_cancel(IPPROTO_TCP, 0xb3, 0xb4);
  pressure_cancel(IPPROTO_ICMP, 0xb5, 0xb6);
  CHECK(ker_rx_ring_cleanup(&rx) == 0 && ker_worker_cleanup(&worker) == 0);
  CHECK(ker_transport_receiver_unregister(&ip_receiver) == 0 &&
        ker_arp_receiver_unregister(&arp_receiver) == 0);
  CHECK(ker_receive_runtime_cleanup(&runtime) == 0 &&
        ker_ipv4_address_cleanup(&address) == 0 &&
        ker_eth_device_cleanup(&device) == 0);
  CHECK(ker_tx_export_cleanup(&exact_tx) == 0 &&
        ker_tx_export_cleanup(&normal_tx) == 0 &&
        ker_tx_ring_cleanup(&ring) == 0 &&
        ker_skb_context_cleanup(&context) == 0 &&
        rte_mempool_avail_count(pool.mbufs) == POOL_SIZE &&
        ker_packet_pool_cleanup(&pool) == 0 && ker_memory_shutdown() == 0 &&
        rte_eal_cleanup() == 0);
  puts("configured ring: mixed protocol dispatch, checksum completion, drops "
       "and cancellation passed");
  return 0;
}
