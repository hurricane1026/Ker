# F-Stack 测试场景迁移

F-Stack 的 tests/unit 和 tests/integration 主要针对 lib/ff_* glue layer；
unit 使用多种 stub/wrap，部分 integration 启动实际 EAL，但也用 stub 替代
FreeBSD mbuf/veth。这不是可直接搬入 Ker 的 Linux TCP/IP 一致性套件。
当前迁移固定到 F-Stack dev commit 646a641cfff77f4815e1e29829a09e1ed15a2999。

按原始场景意图适配 Ker 真实实现的 F-Stack 场景当前共 14 个独立 CTest 用例。测试
实现重新编写，使用 Ker CHECK harness 和真实 EAL/mempool，不复制 ff_* glue、
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
| fstack-headroom-export | test_ff_dpdk_if_send_basic | 显式 headroom 转为 mbuf data_off，检查字节和 skb 释放后的副本生命周期 |
| fstack-multiseg-copy | test_ff_dpdk_if_send_multiseg | 真实多段 DPDK 输入复制并合并到线性 Linux skb，检查零长度段、源链所有权和释放源链后的数据；不代表上游分段 TX 或 Linux nonlinear skb 支持 |
| fstack-multiseg-ethernet-ingress | test_ff_dpdk_if_send_multiseg | 将目的/源 MAC 和 EtherType 拆分到真实 DPDK 段中，经 Ker copy adapter 线性化后调用原始 Linux Ethernet 分类器，并经现有协议 runtime 分发；方向改为 ingress，不宣称 F-Stack TX、NIC/offload 或 Linux nonlinear skb |
| fstack-arp-chain-feedback | test_ff_dpdk_if_send_multiseg | Ker-specific integration extension：将有效 ARP reply 的以太网和 ARP 字段拆分到 DPDK chain，经 copy/classify、原始 ARP decoder 和实际 worker RX poll，验证现有 scoped neighbor feedback 从 DELAY 更新至 REACHABLE。该 ARP feedback 场景不是 F-Stack 上游测试，不代表一般 ARP learning 或 NIC 收发 |

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
- 新增的 `ker_eth_receive_copy_chain` 在 copy-in 后调用未修改的 `eth_type_trans`，并允许既有协议 runtime 处理分类后的 skb；源 mbuf 链仍由调用者持有。后续正向 TX/网卡与 offload 场景需独立实现这些能力后再接入。
- 在真实 ethdev TX 与 offload capability/metadata 协商接入后，再新增 checksum、TSO、UDP checksum 的正向发送场景；当前 fstack-offload-metadata-rejection 仅锁定 fail-closed 边界和重试，不代表功能追平。
- 有 RSS、跨 worker 转发、设备管理能力后，适配 flow-map、drain/reload 场景；
  当前 FIFO 测试不代表这些并发/多进程能力。
- 有 Ker socket/epoll API 后，再引入 TCP/UDP 应用互通、连接回收、超时等黑盒
  场景。FreeBSD kqueue/内部 mbuf 的白盒测试不直接用于原始 Linux 布局。
- 在实际移植配置、日志、pcap 或 IPC 模块后，再选择对应 ff_* glue 用例；
  当前项目没有这些接口，不能靠空 stub 建立虚假覆盖。

该套件是外部场景驱动的补充，既有 Linux 原始代码、DPDK 所有权和失败回滚
测试继续保留。当前公共网络 capability 仍仅为 checksum。
