# Worker 轮询与 RX 压力

当前提供私有 `ker_worker` 轮询框架，用于接入后续网络设备适配。它组合已有
Linux timerqueue 调度、每 worker 分类内存压力与原生 DPDK 包池可用量。
没有接入 ethdev、net_device、NAPI、IP/UDP/TCP 或公共 socket API。

## 一轮工作

`ker_worker_poll(worker, now_ns, result)` 按顺序执行：

1. 在 timer_budget 内触发到期定时器。
2. 在 service_budget 内推进已有应用/协议任务。
3. 在 tx_budget 内推进适配层提供的发送重试与完成回收。
4. 观察分类内存水位及本 lcore 可获取的 mbuf 描述符快照。
5. 若无压力，按 RX 配置与可用量计算预算并调用接收适配器。

定时器预算必须非零。service、TX 和 RX 可以以零预算关闭；非零预算必须
提供对应回调。回调同步运行且必须返回不超过预算的工作数或负 errno，
不能阻塞、重入轮询、注销 worker、关闭或重建所借用的 pool/runtime。
框架不接管回调创建的包；适配器仍必须遵守 DPDK 分配/归还与发送所有权。
service 只推进已有任务，不能借此绕过新请求接入限制。

容量压力只暂停 RX。应用/协议任务、定时器和 TX 不受这个门控限制，因而
可以释放已经持有的对象；回收后同一轮重新观察水位并恢复 RX。若回调失败，
停止本轮后续阶段并返回错误；result 报告已成功完成的阶段，失败回调自己的
部分副作用无法由框架回滚。返回超过预算的正数会被识别为 EPROTO。

## 包池可用量与门控

`ker_packet_pool_available` 读取 mempool backend 的 get_count 与当前 lcore
默认 cache 的长度。固定版本 DPDK 的公开内联 get/put 路径同样使用 ops 表；
ker 在私有适配层通过该表调用计数回调，避免依赖未导出的 get_count wrapper。
本地 ring handler 的计数不扫描所有 lcore。其他 handler 的性能须单独验证。

DPDK 的 `rte_mempool_avail_count/in_use_count` 会遍历所有默认 lcore cache，
其源码明确限定为诊断用途，因此不在本轮询热路径使用。其他 lcore 的缓存
和 user-owned cache 不属于当前 worker 可立即取得的容量，不计入这个快照。
测试验证外核缓存保有空闲对象时，本核快照相应减少；外核主动 flush 后恢复。

快照是建议值，另一个 worker 可以随后消耗公共池；真正分配仍可能失败，
必须处理 NULL。计数来自 DPDK 原生池，原生分配、indirect clone 和最终
backing 释放均可见，没有另造包引用计数或依赖 ker_packet_free 拦截归还。
它数的是可获取的描述符，不能代替共享 backing 字节数、socket 内存或连接额度。

`packet_low`/`packet_high` 表示可用描述符的低/高水位。降到 low 或以下时
暂停 RX，只有恢复到 high 或以上才重新开放。high 为零关闭这项迟滞。
三类内存域中任一项处于压力状态也暂停 RX。没有压力时，RX 工作预算取
`rx_budget` 与 `packet_available - rx_margin` 的较小值，差值非正则不接收。

rx_margin 是入站预算的建议余量，**不是隔离的控制报文预留池**：其他 worker、
PMD 或回调的额外分配可能消耗它，一个接收工作也可能需要多个描述符。
这套门控还不能保证 TCP ACK、窗口推进或攻击流量下的控制报文存活；独立
控制资源、连接预算与协议级 admission 策略需要在真实协议入口接入时实现。

## 生命周期与验证

先初始化 EAL、所属 worker 的 memory context 和 packet pool，随后用零初始化
的 worker 调用 init。worker、pool 结构及回调参数地址必须稳定，所有 worker
操作属于同一 lcore。poll 接收单调不回退的纳秒时间；本地事件屏蔽和重入时
拒绝调度。调用者负责外层循环和时间获取。

cleanup 取消待处理定时器，不触发回调，不销毁借用的包池或 memory context。
随后由调用者归还包、关闭包池和内存上下文。若包池在轮询前已关闭，poll
拒绝执行回调；不同线程调用也被拒绝。没有独立在线 worker 销毁或 RCU 回收。

真实 EAL 测试覆盖缓存与 native clone 的可用量、外核 cache flush、按余量缩小
RX 预算、高低水位恢复、压力下 timer/service/TX 的推进、应用释放后立即恢复、
回调错误与超预算、重入和错误 worker，以及关停取消待处理定时器。
尚未验证真实 PMD、线速性能、多 NUMA 或 TCP 压力正确性。
