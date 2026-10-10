# 单 worker 原始 NAPI 调度与完成

直接编译固定 Linux `net/core/dev.c` 中的 `napi_schedule_prep()` 与
`napi_complete_done()`，并导入完整原始 `napi_struct`、GRO 布局、hrtimer、
work_struct、IRQ notifier 与 cpumask 类型。输入由 SHA256 manifest 固定，
每个选定代码块逐字保留并记录来源偏移、行号、摘要和版权。没有直接编译完整
`dev.c`，也没有将简化的自定义结构命名为 Linux napi_struct。

原始状态转换负责 SCHED/MISSED：首次调度取得所有权，重复调度记录 MISSED；
完成时若有 MISSED，保留 SCHED 并重新排队，再执行一轮。实际 `__napi_schedule`
由 ker 适配为单 worker 的 intrusive queue，原始完成函数的 IRQ 屏蔽由已有
用户态 IRQ 层提供，cmpxchg 使用真实原子 compare-exchange。

## worker 队列与预算

私有 `ker_napi_runtime` 和 `ker_napi` 为调用方提供的稳定存储，初始化为零，
所有操作与 driver poll 回调限于同一个已初始化 EAL/memory worker。没有跨核
IRQ 或并发队列。原始 cpumask 在私有配置下使用 RTE_MAX_LCORE 作为 NR_CPUS，
不声称与运行中内核的 ABI 一致。NAPI context 从 init 到 cleanup pin 设备，
即使 disabled/没有 skb，也阻止释放它借用的 net_device；runtime 与 device
必须比 NAPI context 活得更久。

每次 runtime poll 快照入口已有队列，公平执行至多一轮，每个回调预算为
min(weight, 剩余总预算)。耗尽预算的 NAPI 保持排队，新调度与重轮询等下次
调用；因总预算不足而尚未处理的旧工作优先于已处理的重轮询。返回不足预算
时 driver 必须调用 complete，且一次回调只能完成一次。非法计数、不完成的
短回调和回调负 errno 会明确报告错误；仍持有 SCHED 的节点保留在队列，便于
重试或在轮询外 disable。已发生的回调副作用不回滚。

runtime poll 的零预算不执行 RX 回调，不实现内核零预算 TX-only poll 约定。
ker 的 enable/disable 是显式的非阻塞生命周期适配，不是原始 napi_enable/
napi_disable 的设备注册、hash、RCU 或线程实现。disable 在轮询外取消队列，
轮询中 enable/disable/cleanup 和递归 poll 返回 EBUSY。驱动回调可 schedule
自己或其他已初始化的 NAPI，但不能复制、移动、释放对象或直接修改 native
调度字段。原始入口是内部实现，仅允许通过带校验的 ker 包装使用。

worker 的 RX 回调可调用 runtime poll。现有压力门控会暂停该阶段，保留已调度
工作；释放 mbuf、恢复水位后继续 RX。timer/service/TX 阶段仍按原顺序推进。
该阶段没有真实 PMD 中断、net_rx_action softirq、完整 __napi_poll 或协议分发。

## 未支持的服务与验证

GRO 缓存必须为空，gro_flush_normal 仅接受真实的空队列；遇到聚合数据会失败，
不会静默丢弃。deferred IRQ、GRO flush timeout、busy-poll、threaded NAPI、
netpoll、BPF 和可选结构配置均明确拒绝。原始完成函数中 hrtimer_start 分支
在有效配置下不可达；如果越过内部契约进入该分支会中止，而非伪装定时成功。
没有 NAPI ID hash、设备注册、IRQ notifier 或线程服务。

真实 DPDK EAL 测试验证重复调度、MISSED 完成重排、回调内重调度、权重与总预算、
公平轮询、零预算、错误计数/负返回值/缺失或重复完成、错误 worker、设备 pin、
取消队列与回收。使用 native mbuf 耗尽与恢复验证压力门控，以及 NAPI driver →
原始 Ethernet 分类 → 测试消费者释放的路径。测试中的 IP EtherType payload
不是有效 IPv4 报文，不代表 ARP/IPv4 已处理。导入测试验证逐字代码、稳定输出、
输入变更拒绝及 CONFIG/MODULE 失败边界。

协议匹配与投递已接入，范围见 [协议分发边界](linux-receive.md)。
下一步接入地址/邻居配置与原始 ARP 和 IPv4/ICMP 入口。
公开能力仍仅为 checksum；网络 API 与真实收发性能仍待后续验证。
