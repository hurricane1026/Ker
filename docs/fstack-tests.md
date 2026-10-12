# F-Stack 测试场景迁移

F-Stack 的 tests/unit 和 tests/integration 主要针对 lib/ff_* glue layer；
unit 使用多种 stub/wrap，部分 integration 启动实际 EAL，但也用 stub 替代
FreeBSD mbuf/veth。这不是可直接搬入 Ker 的 Linux TCP/IP 一致性套件。
当前迁移固定到 F-Stack dev commit 646a641cfff77f4815e1e29829a09e1ed15a2999。

适配场景由下表逐项列出，各自运行独立 CTest。测试实现重新编写，使用 Ker CHECK
harness 和真实 EAL/mempool，不复制 ff_* glue、
FreeBSD 栈、cmocka mock/stub 或覆盖率脚本。没有通过宿主机 socket 的结果
冒充 Ker 网络栈通过，也不因 EAL 初始化失败跳过用例。

| Ker CTest | 上游场景 | 适配边界 |
|---|---|---|
| fstack-mbuf-release | test_ff_dpdk_pktmbuf_free_basic | 实际 Ker packet pool alloc/free，验证可用对象数恢复 |
| fstack-clock-monotonic | test_ff_get_tsc_ns_monotonic | Ker CLOCK_MONOTONIC ns，验证非递减，不复制 TSC 算法 |
| fstack-empty-export | test_ff_dpdk_if_send_zero_total | 空 skb copy-export，断言长度和所有权，不宣称网卡发送 |
| fstack-null-context | test_ff_dpdk_if_send_null_ctx_no_crash | Ker allocation 拒绝 null context，输出不变 |
| fstack-packet-export | test_ff_dpdk_if_send_basic | 实际字节复制；原始 backing 释放后 copy 仍可读取 |
| fstack-multiseg-boundary | test_ff_dpdk_if_send_multiseg | 当前 Ker ENOTSUP admission 边界，未实现上游的正向多段发送 |
| fstack-queue-isolation | test_ut_nr_19_drain_ring_sp_sc | 两个本地 Linux skb FIFO 隔离，不等价于多进程 generation/ring |
| fstack-queue-full-ownership | 同上 | 满队列不消费调用方引用，可用 pool 对象数不变 |
| fstack-export-exhaustion-retry | test_ff_dpdk_if_send_copydata_fail | 真实 pool 耗尽时输出槽和 skb 所有权不变；释放一个 mbuf 后重试成功，不模拟 copydata 错误 |
| fstack-offload-metadata-rejection | test_ff_dpdk_if_send_ip_csum / test_ff_dpdk_if_send_tso | Ker 当前明确拒绝无法执行的 checksum/GSO 元数据，验证对象不变并在清除标记后成功导出；不宣称正向 offload |
| fstack-software-checksum-completion | test_ff_dpdk_if_send_ip_csum | Ker-specific software completion extension：复制线性 CHECKSUM_PARTIAL skb，并以 Linux Internet-checksum primitives 在副本上完成 UDP/TCP pseudo-header-seeded checksum；CRC32C（当导入 skb layout 暴露该标志时）、GSO 与普通 export 仍 fail-closed，输出无 TX offload flag，不代表 F-Stack 网卡 offload |
| fstack-headroom-export | test_ff_dpdk_if_send_basic | 显式 headroom 转为 mbuf data_off，检查字节和 skb 释放后的副本生命周期 |
| fstack-multiseg-copy | test_ff_dpdk_if_send_multiseg | 真实多段 DPDK 输入复制并合并到线性 Linux skb，检查零长度段、源链所有权和释放源链后的数据；不代表上游分段 TX 或 Linux nonlinear skb 支持 |
| fstack-multiseg-ethernet-ingress | test_ff_dpdk_if_send_multiseg | 将目的/源 MAC 和 EtherType 拆分到真实 DPDK 段中，经 Ker copy adapter 线性化后调用原始 Linux Ethernet 分类器，并经现有协议 runtime 分发；方向改为 ingress，不宣称 F-Stack TX、NIC/offload 或 Linux nonlinear skb |
| fstack-arp-chain-feedback | test_ff_dpdk_if_send_multiseg | Ker-specific integration extension：将有效 ARP reply 的以太网和 ARP 字段拆分到 DPDK chain，经 copy/classify、原始 ARP decoder 和实际 worker RX poll，验证现有 scoped neighbor feedback 从 DELAY 更新至 REACHABLE。该 ARP feedback 场景不是 F-Stack 上游测试，不代表一般 ARP learning 或 NIC 收发 |
| arp-configured | RFC 826 §2 (format reference; Ker-specific test) | 使用显式静态 IPv4 address 和调用方 MAC tuple 调用原始 ARP request/reply constructor；按42个wire bytes验证broadcast/zero-THA request、reply与旧 raw adapter 等价，并覆盖失败回滚。既有 arp-receive 测试另覆盖 DAD、Ethernet padding、malformed fields、copied-message lifetime 和 callback ownership。无 neighbor lookup、自动应答、路由或 NIC 收发 |
| fstack-ipv4-ingress-validation | test_ff_dpdk_if_send_multiseg / test_ff_dpdk_if_send_ip_csum | Ker-specific ingress extension：真实 EAL segmented Ethernet/IPv4 frame 经 copy/classify 后，以原始 `ip_fast_csum` 检查 IPv4 base/options header，验证长度、padding、fragment 字段和失败所有权。Pinned F-Stack 两个用例都是 TX 路径，没有 IPv4 ingress/header-validation case；本测试不模拟 `ip_rcv`、路由、reassembly、transport/socket 或 NIC delivery |
| fstack-udp-ingress-validation | test_ff_dpdk_if_send_udp_csum | Ker-specific ingress extension：真实 EAL segmented UDP/IPv4 datagram 经已有 IPv4 view 后，用原始 Linux pseudoheader checksum helpers验证偶数/奇数payload、checksum零值语义和长度/fragment/协议失败。Pinned F-Stack case仅设置TX UDP checksum offload并调用 send；不覆盖UDP ingress，也不代表socket、路由、reassembly、ICMP、NIC或TX offload |
| fstack-udp-minimal-boundaries | test_ff_dpdk_if_send_udp_csum | Additional Ker-specific real-EAL regression：minimum 8-byte UDP headers with zero/nonzero checksum, both ports zero, even payload and Ethernet padding exclusion; independent checksum oracle plus source/copy lifetime checks. Upstream case remains TX-only |
| fstack-tcp-ingress-validation | test_ff_dpdk_if_send_tcp_csum | Ker-specific ingress extension：真实 EAL segmented IPv4/TCP，经原始 IPv4 view 后校验完整 TCP pseudoheader checksum、20–60 byte header/data offset和opaque options。Pinned F-Stack case只覆盖TCP TX checksum offload。本测试不解释 TCP options、不实现连接状态、routing、reassembly、socket或NIC delivery |
| transport-receive | test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum | Ker-specific actual-worker RX integration：ETH_P_IP handler 验证 IPv4 后同步交付 borrowed IPv4/UDP/TCP views；分段源链在 dispatch 前释放，验证 checksum/fragment/protocol rejection、callback DROP/invalid status、回调期 unregister/cleanup EBUSY 和多 handler fanout 对共享 skb descriptor 的 fail-closed `-EBUSY`。Views 只能在同步 callback 内读取，不得保留、修改或释放；共享 descriptor 不交付。ICMP echo request/reply 后续在独立 `icmp-echo` case 覆盖。上游场景是 TX offload；此用例不代表 socket、routing、reassembly、TCP state 或 NIC delivery |
| icmp-echo | test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum | Ker-specific ICMPv4 echo extension following [RFC 792](https://www.rfc-editor.org/rfc/rfc792.html): constructs explicit-address Ethernet/IPv4 echo request/reply packets with opaque IPv4 options and full ICMP checksum, then validates echo type/code/checksum through immutable views and the actual worker transport receiver. ICMP checksum zero is retained as computed; this is not automatic reply, ICMP error handling, ping, routing, reassembly, socket or NIC support. The pinned F-Stack cases cover UDP/TCP TX offload, not ICMP |
| ipv4-field-profiles | test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum / test_ff_dpdk_if_send_multiseg | Ker-specific UDP/TCP/ICMP echo constructor extension: copies an opaque IPv4 DS byte and wire-order identification, permits only fragment field zero or DF, and checks IPv4 and transport checksums with independent byte oracles. Permanent-neighbor variants snapshot the configured source and neighbor MAC; a concurrent 192-packet three-protocol TX/RX case checks copied fields on real worker threads. RX-ring tests also preserve a DF profile through exact software checksum completion, allocation-pressure cancellation and FIFO recovery. This does not change RX handling of the raw IPv4 reserved fragment bit. Existing constructors remain byte-identical zero-profile wrappers. The pinned cases do not test these IPv4 fields; this adds no DSCP/ECN policy, ID generation, fragmentation, PMTU, routing or NIC behavior |
| icmp-neighbor-create | test_ff_dpdk_if_send_udp_csum | Ker-specific extension builds ICMP echo packets from one configured local address/device and an existing permanent neighbor, releases the lookup reference before allocation, and verifies options/checksum through TX retry and worker RX. The upstream case does not test ICMP or neighbor selection; no ARP resolution, routing, automatic reply, ICMP errors, ping, socket or NIC behavior is claimed |
| icmp-chain-exact-fold | test_ff_dpdk_if_send_multiseg / test_ff_dpdk_if_send_udp_csum | Ker-specific opt-in software checksum completion preserves a folded zero in a copied DPDK chain and verifies it through actual worker RX with ring backpressure. The legacy checksum mode continues its existing zero-mangling behavior. This is not hardware offload and does not define other protocols' zero policy |
| udp-create | test_ff_dpdk_if_send_udp_csum | Ker-specific software packet-construction/roundtrip extension：显式地址/端口构造 Ethernet+IPv4+UDP owned skb，Linux checksum primitives 生成 IP/UDP checksum，再 copy-export、拆段并经实际 worker transport receiver 校验。输入 payload 被复制；不代表上游 TX offload、路由、地址策略、socket 或 NIC发送 |
| udp-ip-options | test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_multiseg | Ker-specific extension adds opaque IPv4 option bytes to explicit Ethernet/IPv4/UDP construction, checks the variable-IHL IPv4 and UDP pseudoheader checksums, then exports and receives a segmented copy through the actual worker path. Options are copied byte-for-byte but not interpreted; the upstream cases motivate checksum and segmented-buffer coverage, not IPv4 options behavior. No routing, source-route processing, socket delivery or NIC transmission is claimed |
| udp-neighbor-create | test_ff_dpdk_if_send_udp_csum | Ker-specific extension derives the source IPv4/MAC from its configured address/device and destination MAC from an existing permanent neighbor entry, releases the lookup reference before allocation, then exercises TX retry and segmented worker RX. It does not perform ARP resolution, FIB lookup, routing, source selection, socket delivery or NIC transmission |
| udp-neighbor-ip-options | test_ff_dpdk_if_send_udp_csum | Ker-specific neighbor-backed UDP constructor extension copies opaque IPv4 options, verifies variable-IHL/IP and UDP checksums, reference release, rollback and worker RX retry. No upstream neighbor/options scenario, ARP resolution, routing, source fallback, socket or NIC behavior is claimed |
| tcp-create | test_ff_dpdk_if_send_tcp_csum | Ker-specific explicit-address Ethernet/IPv4/TCP construction and worker receive-roundtrip extension: software checksums are checked by an independent byte oracle, a TX sink backpressure retry exports a copy, and the accepted copy is segmented before native Ethernet classification and TCP view delivery. This does not implement TCP connection state, sockets, routing, NIC transmission or hardware offload |
| tcp-options | test_ff_dpdk_if_send_tcp_csum | Ker-specific extension constructs TCP headers with copied opaque 0–40-byte aligned options and verifies the complete checksum after TX retry, segmentation and worker receive. The pinned F-Stack case is TX checksum-offload only; Ker does not interpret options or add TCP state/socket/NIC support |
| tcp-ip-options | test_ff_dpdk_if_send_tcp_csum / test_ff_dpdk_if_send_multiseg | Ker-specific extension constructs IPv4/TCP packets with independently supplied opaque IPv4 and TCP option bytes, checks both header checksums with independent wire oracles, then exports a real segmented copy through worker TX/RX. Existing no-IP-options APIs remain zero-option wrappers. The F-Stack cases motivate checksum/segmentation coverage, not option semantics; no routing, source-route processing, TCP state, socket or NIC behavior is claimed |
| tcp-neighbor-create | test_ff_dpdk_if_send_tcp_csum | Ker-specific extension derives source IPv4/MAC from one configured address/device and destination MAC from an existing NUD_PERMANENT neighbor, releasing the lookup reference before allocation. It tests TCP options/checksum through TX retry and segmented worker RX; upstream does not test neighbor selection or ARP. No unresolved queue, FIB, routing, source fallback, TCP state, socket or NIC transmission is claimed |
| tcp-neighbor-headers | test_ff_dpdk_if_send_tcp_csum | Ker-specific combined neighbor constructor copies independent opaque IPv4/TCP options (including 40-byte areas), verifies both checksums and lookup-reference release before allocation, then exercises worker TX/RX retry. Existing TCP neighbor API/error precedence stays unchanged; no option interpretation, ARP resolution, routing, TCP state, socket or NIC transmission is claimed |
| fstack-chain-export | test_ff_dpdk_if_send_multiseg | Ker-specific positive copy extension: copy a supported linear UDP/TCP constructor skb into a caller-owned direct DPDK chain, release the source, then receive the chain through existing copy/classify and worker transport validation. This is not native Linux nonlinear skb support, upstream F-Stack TX, NIC transmission or offload |
| tx-chain-export | test_ff_dpdk_if_send_multiseg | Ker-specific worker TX retry extension: opt-in `CHECKSUM_NONE` mode copies a supported linear skb to a direct DPDK chain; sink acceptance transfers the whole chain, while rejection frees the copy and retains the original FIFO skb for retry. Legacy single-mbuf software-checksum export remains separate. This is not F-Stack/NIC transmission, nonlinear Linux skb support, or hardware offload |
| fstack-chain-software-checksum | test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum | Ker-specific software-completion extension: completes a linear `CHECKSUM_PARTIAL` skb using Linux checksum semantics, copies it into direct DPDK segments even when the checksum word crosses a segment boundary, then validates UDP/TCP through native Ethernet classification and the actual worker receiver. Coverage includes variable IPv4 IHL with checksum start after the full options area. The pinned F-Stack cases exercise TX checksum offload; this does not claim NIC/hardware offload, nonlinear Linux skb support, sockets or TCP state |
| tx-ring-drain | test_ff_dpdk_if_send_multiseg | Ker-specific application-ring transport extension: worker TX copies into a bounded exact-capacity DPDK pointer ring with SP/SC flags; a single consumer drains whole chains and feeds the existing copy/classify worker RX path. Ring-full returns EAGAIN so the TX exporter retains the original skb for retry. This does not implement an ethdev, NIC/RSS, multi-process sharing or F-Stack TX |
| rx-ring-drain | test_ff_dpdk_if_send_multiseg | Ker-specific worker RX extension over the application ring: one attached consumer copies accepted direct chains into owned Linux skbs and dispatches them through the existing Ethernet and IPv4 transport receive path. Allocation pressure retains the popped chain for retry; option-bearing UDP/TCP frames preserve FIFO order through retry and cancel; ICMP echo is delivered and a bad ICMP checksum is consumed as a drop without callback. This does not implement ethdev RX, NIC/RSS, NAPI polling or sockets |
| fstack-concurrent-ring | test_ff_dpdk_if_send_multiseg / test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum | Ker-specific concurrent same-process SP/SC integration: a capacity-one ring is filled before its registered EAL consumer starts, forcing TX-export retry, then producer A and consumer B overlap for 192 alternating UDP/TCP/ICMP echo chains across repeated ring wraparound. IPv4 and TCP option lengths vary and are checked byte-for-byte after RX. The consumer uses its own worker, memory context, pool, device and actual RX dispatcher. It does not claim MPMC, multiprocess/RSS, NIC I/O or F-Stack RX |
| cross-worker-ring-rx | test_ff_dpdk_if_send_multiseg | Ker-specific same-process SP/SC extension: an EAL worker A exports UDP/TCP chains into a DPDK ring and a distinct worker B uses its own pool, context, device and actual worker RX poll to classify and validate them. Pool pressure preserves FIFO pending ownership for retry. Producer/consumer lifecycle changes require external quiescence; this does not claim RSS steering, multiprocess rings, NIC I/O or F-Stack RX |
| tx-chain-software-checksum | test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum | Ker-specific worker TX extension: the opt-in chain exporter accepts ordinary `CHECKSUM_NONE` and supported Internet `CHECKSUM_PARTIAL` packets. It completes each partial checksum in an independent chain copy; sink rejection frees that copy and retains the unchanged original for FIFO retry. Existing CHECKSUM_NONE-only chain mode and legacy single-mbuf completion remain separate. This does not claim NIC/hardware offload, nonlinear Linux skb support, sockets or TCP state |
| tx-copy-export-retry | test_ff_dpdk_if_send_udp_csum | Ker-specific worker TX copy/retry extension: bounded owner-worker FIFO retains the original skb until a synchronous application sink accepts its copied mbuf; allocation and sink backpressure preserve the pending head, and cancellation returns it before later FIFO entries. The sink is not an ethdev/NIC, and this does not implement F-Stack hardware offload or transmission |

逐例上游路径、case 名、固定版本和原始文件 SHA256 记录于
[provenance](../tests/fstack-provenance.json)。源链接固定到具体 commit；这是
场景追溯记录，不宣称生成或逐字执行原始 suite，也没有把上游 README 的测试
数量/覆盖率数字当成 Ker 的实测结果。

运行：

```bash
ctest --test-dir build -R '^fstack-' --output-on-failure
```

这些用例仅随 KER_WITH_DPDK 启用。每例独立进程，使用现有无 hugepage/无 PCI
EAL 测试初始化，显式检查全部 descriptor、queue 和 pool 回收。DPDK 沿用
项目固定 submodule 版本，不替换成上游 Makefile 的主机版本。

## 后续迁移顺序

- 新增的 `ker_skb_copy_from_mbuf_chain` 仅将经校验的独占 direct DPDK 输入链复制成线性 skb；`ker_skb_from_mbuf` 仍拒绝多段 adopt，且此适配不保留 DPDK 分段边界。下一步若实现 Linux skb 非线性片段语义及相应 DPDK 引用生命周期，再测试原生分段 skb 导出；当前用例不宣称上游多段 TX 正向支持。
- `ker_skb_to_mbuf_chain_copy` 为受支持的 owned 线性 skb 创建独立 direct DPDK chain，首段保留 skb headroom、后续段用默认 headroom，并在失败时释放所有部分分配；既有单段 `ker_skb_to_mbuf` 不变。它仅提供显式复制，不暴露 Linux skb fragment/list 语义，也不代表 NIC/offload 或 F-Stack 原生发送路径。
- 新增的 `ker_eth_receive_copy_chain` 在 copy-in 后调用未修改的 `eth_type_trans`，并允许既有协议 runtime 处理分类后的 skb；源 mbuf 链仍由调用者持有。后续正向 TX/网卡与 offload 场景需独立实现这些能力后再接入。
- 在真实 ethdev TX 与 offload capability/metadata 协商接入后，再新增 checksum、TSO、UDP checksum 的正向发送场景；当前 fstack-offload-metadata-rejection 仅锁定 fail-closed 边界和重试，不代表功能追平。
- `ker_skb_to_mbuf_software_checksum` 仅为线性 Internet-checksum CHECKSUM_PARTIAL skb 提供软件 completion 副本；当导入的 skb layout 暴露 `csum_not_inet` 时会拒绝 CRC32C，且始终拒绝 GSO。它与 F-Stack 原用例的 NIC offload path 不同，也不改普通 `ker_skb_to_mbuf` 的 fail-closed 约束。
- `ker_skb_to_mbuf_chain_software_checksum_exact` 和对应显式 TX mode 保留折叠结果为零的字节；旧 checksum API 仍将 Internet checksum 的零映射为 `CSUM_MANGLED_0`。`CHECKSUM_NONE` 仍按普通复制处理。调用方负责选择协议要求的零值策略；此选项不宣称 NIC/offload。
- `ker_ipv4_packet_view_init` 只验证owned/classified linear IPv4 skb的完整header/options、total length和原始checksum，并借出只读view；不改变 skb 长度，padding留在原位置，fragment字段只是原始wire-order值。此项是Ker-specific extension，非上游IPv4 ingress场景，无fragment reassembly、FIB、netfilter、L4或socket处理。
- `ker_udp_packet_view_init` 进一步验证 unfragmented IPv4 UDP 的完整固定头、精确匹配的UDP/IP长度及伪首部checksum；合法IPv4 UDP零checksum按协议作为checksum omitted接受。UDP头/负载以只读borrowed pointers返回，保留wire-order字段，不修剪padding、不送socket，也不信任RX checksum元数据跳过软件校验。该场景由TX-only F-Stack UDP checksum用例启发，属于Ker-specific ingress扩展。
- `ker_tcp_packet_view_init` 进一步验证unfragmented IPv4 TCP segment、完整 TCP pseudoheader checksum、最小/最大data offset及完整segment bounds；TCP checksum字段值零不作为省略标志，只按同一校验算法验证。Header options保持opaque，不做解释；不修改skb、不做routing、reassembly、TCP状态机或socket处理。此 ingress view 是受 F-Stack TX checksum案例启发的Ker-specific extension。
- 有 RSS、跨 worker 转发、设备管理能力后，适配 flow-map、drain/reload 场景；
  当前 FIFO 测试不代表这些并发/多进程能力。
- 有 Ker socket/epoll API 后，再引入 TCP/UDP 应用互通、连接回收、超时等黑盒
  场景。FreeBSD kqueue/内部 mbuf 的白盒测试不直接用于原始 Linux 布局。
- 在实际移植配置、日志、pcap 或 IPC 模块后，再选择对应 ff_* glue 用例；
  当前项目没有这些接口，不能靠空 stub 建立虚假覆盖。

该套件是外部场景驱动的补充，既有 Linux 原始代码、DPDK 所有权和失败回滚
测试继续保留。当前公共网络 capability 仍仅为 checksum。
