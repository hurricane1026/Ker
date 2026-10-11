# 原始邻居布局与永久 IPv4 邻居表

完整导入原始 neighbour、neigh_table、neigh_hash_table、neigh_parms、neigh_ops、
statistics、skb queue、hh_cache 和依赖布局。ARP hash、IPv4 key equality、
___neigh_lookup_noref/__neigh_lookup_noref、neigh_clone、parameter reference
helpers 与 neigh_ha_snapshot 均逐字保留。输入由 SHA256 固定，选定片段保留
版权、来源、行号、偏移和摘要。没有直接编译完整 neighbour.c 或动态状态机。

## 有效状态与资源

每张私有表属于一个配置了静态 IPv4 地址的 Ethernet 设备和一个 worker。
只接受手工安装的 NUD_PERMANENT 条目，IP→MAC 在 publication 后不可变；
重复 key 返回 EEXIST，更新需先删除再新增。NUD_PERMANENT 是 Linux 原始
不做地址解析、不会被 GC 删除的 pseudostate，不宣称已经实现动态解析。

完整表和 bucket 数组走真实 DPDK GFP_KERNEL control allocation。记录来自
独立固定 kmem_cache/mempool，GFP_ATOMIC 分配没有 heap、libc 或更大池回退。
逻辑 limit 与底层固定池容量分别控制：前者满时 ENOSPC，后者或容量预算
不足时 ENOMEM。固定池对象数沿用 ker_memory_init 的 cache_objects 配置，
不是 limit 参数；配置时应同时考虑对象数、域预算和 hash bucket 数量。
hash_bits 为 1..16，表不在线扩容。初始化分阶段失败会回收此前取得的资源。

使用原始 ARP hash 对 key 和真实设备指针计算 bucket。当前使用固定奇数
multiplier，碰撞仍由完整 key 与设备比较确认；它不提供随机化或攻击防御
保证，表不接收报文驱动的学习更新，链长受配置的容量和固定资源约束。

## 引用与生命周期

表 owns 一个 IPv4 address/in_device 引用，并将自己的原始 neigh_parms 关联
到 in_device.arp_parms。地址的既有 device/context pin 保证依赖不被提前释放。
每条记录 owns 一个 parameter 引用，表 owns 一个记录引用；lookup 用原始 neigh_clone
再给调用方一个记录引用。所有 lookup 引用必须通过 release 归还，未归还时
remove 返回 EBUSY。不能把归还后的裸指针继续当作有效 handle。

MAC snapshot 使用真实 sequence 状态进行 acquire 读取与 retry，读取适配
不会伪装为常量成功。永久 MAC 不在线修改，读写由 worker 生命周期串行化。
原始 seqcount/seqlock 布局保留，嵌入 spinlock 使用既有真实原子锁；rwlock
使用真实 pthread primitive，并在分配/回收时初始化/销毁。辅助锁不是完整
内核 preemption、lockdep 或跨核 RCU 实现。

原始 RCU/hlist traversal 在私有 profile 下使用真实本地链接与原子 pointer
读取；没有 grace-period reclamation。init/cleanup 是离线操作，要求没有活
skb、绑定 NAPI 或设备协议/dispatch pin。cleanup 还要求表无记录、没有额外
parameter 引用；先断开 arp_parms、释放地址引用，再销毁固定池和表资源。
add/remove/lookup/release/snapshot 只能由同一个初始化 worker 调用。native
字段和链接归实现所有，调用方不得直接更改它们或启动未移植的工作/定时器。

## 边界和验证

ARP parms 提供对象/设备关联、引用基础及显式离线 timing/probe 参数配置。
受监视条目运行原始 probe/retry timer，并可在 probe callback 内通过
[native ARP probe adapter](linux-arp-probes.md) 取得构造出的 skb。GC/managed
work、pending skb/proxy queues、header cache、一般 ARP learning、neigh_event_send、
完整 arp_process、自动应答或 PMD 发送仍未接入。`neigh_update` 只通过
[受限的监视条目适配](linux-neighbor-timer.md#restricted-native-neighbor-update) 开放
DELAY/PROBE→REACHABLE；ARP reply 仅能通过
[callback feedback gate](linux-arp-receive.md#explicit-feedback-for-monitored-neighbors)
显式调用此路径。普通永久表项仍保持静态，不会自动解析地址。

真实 EAL 测试覆盖分阶段分配与实际 pool-name 冲突回滚、非法 key/MAC、错误
worker、duplicate key、表上限与底层池耗尽的区别、容量回收和同名重建，
原始 lookup 在碰撞下的 key/device 匹配、引用阻止删除、参数/地址 pin、
原始 MAC snapshot 的输出与 addr_len 拒绝，以及用 snapshot 构造真实 ARP
应答字节。导入测试检查逐字代码、稳定输出、配置与 MODULE 拒绝和源码变更。

下一步接邻居动态更新、发送调度，再接真正的 ARP 接收与 IPv4/ICMP 入口。
公共 capability 仍仅为 checksum，当前无法提供网络服务。

## 离线邻居参数适配

`ker_neighbor_configure` 在空表且无额外 parms 引用、活 skb、NAPI 或协议注册时，
配置明确的 retrans、base reachable、delay tick 数以及 unicast、multicast、
multicast reprobe 次数。timer_list profile 的 tick 为 1ms；没有隐式默认值。
普通永久邻居表仍不发 probe；probe 仅由显式监视器的原生 timer callback 驱动。

原始 `neigh_var_set`、NEIGH_VAR 系列宏、`neigh_set_reach_time` 和
`neigh_rand_reach_time` 均逐字导入并保留来源。原始 set helper 更新真实
`data_state` 位图，并通过 WRITE_ONCE 写参数。适配层仅提供 namespaced
原子 set-bit 与有界随机数 primitive，不改 Linux 函数或数据布局。
随机 reachable time 遵循上游 `base / 2 + random_below(base)`，范围为
`[floor(base/2), base + floor(base/2))`。真实 host getrandom 加拒绝采样
避免 modulo bias；这是离线配置路径，允许等待系统 entropy，不属于包轮询路径。
熵源失败会 fail closed，不能伪装为固定随机结果。

所有 interval 必须非零且能存入 Linux 的 signed int；reachable base 额外限制
为 `2 * floor(INT_MAX / 3)`，保证随机上界不会截断。每个 probe 次数及
unicast 加对应 multicast 总和必须能存入 signed int。0 probes 允许显式禁用。
APP_PROBES 固定为 0 并标记已配置，因为当前没有 ARPD application probe 服务；
其余 proxy、queue、GC 参数仍不启用。全部输入及离线条件通过后才写入字段；
非法配置、错误 worker 或在线状态不会部分修改已有参数。配置不分配 DPDK 内存。

真实 EAL 测试覆盖配置读取、真实 data_state 位图、错误 worker、额外 parameter
引用与活 skb 阻止配置、已有条目阻止重配、无分配路径、非法值原子拒绝，
以及靠近 INT_MAX 的随机范围。导入测试同时校验 neighbour.c 原始随机函数的
逐字代码和 provenance，并拒绝 unreviewed upstream source。
