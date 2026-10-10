# F-Stack 测试场景迁移

F-Stack 的 tests/unit 和 tests/integration 主要针对 lib/ff_* glue layer；
unit 使用多种 stub/wrap，部分 integration 启动实际 EAL，但也用 stub 替代
FreeBSD mbuf/veth。这不是可直接搬入 Ker 的 Linux TCP/IP 一致性套件。
当前迁移固定到 F-Stack dev commit 646a641cfff77f4815e1e29829a09e1ed15a2999。

第一批按原始场景意图适配 Ker 的真实实现，共 8 个独立 CTest 用例。测试
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

- 实现 ethdev/多段/offload 后，接上游相关正向发送场景，保留当前负向 admission
  与 ownership 断言。正向尚未支持时不能将 skip 计为通过。
- 有 RSS、跨 worker 转发、设备管理能力后，适配 flow-map、drain/reload 场景；
  当前 FIFO 测试不代表这些并发/多进程能力。
- 有 Ker socket/epoll API 后，再引入 TCP/UDP 应用互通、连接回收、超时等黑盒
  场景。FreeBSD kqueue/内部 mbuf 的白盒测试不直接用于原始 Linux 布局。
- 在实际移植配置、日志、pcap 或 IPC 模块后，再选择对应 ff_* glue 用例；
  当前项目没有这些接口，不能靠空 stub 建立虚假覆盖。

该套件是外部场景驱动的补充，既有 Linux 原始代码、DPDK 所有权和失败回滚
测试继续保留。当前公共网络 capability 仍仅为 checksum。
