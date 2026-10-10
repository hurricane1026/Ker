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

ARP parms 当前仅提供对象/设备关联和引用基础，data/reachable-time 没有配置
动态 NUD 参数。probe timers、GC/managed work、pending skb/proxy queues、
header cache、output callbacks 和 neighbor learning 不活跃；没有 neigh_update、
neigh_event_send、ARP 收包解析、自动应答或 PMD 发送。上层可取得稳定的永久
MAC 用于现有原始 ARP 构造测试，但这不代表解析流程已实现。

真实 EAL 测试覆盖分阶段分配与实际 pool-name 冲突回滚、非法 key/MAC、错误
worker、duplicate key、表上限与底层池耗尽的区别、容量回收和同名重建，
原始 lookup 在碰撞下的 key/device 匹配、引用阻止删除、参数/地址 pin、
原始 MAC snapshot 的输出与 addr_len 拒绝，以及用 snapshot 构造真实 ARP
应答字节。导入测试检查逐字代码、稳定输出、配置与 MODULE 拒绝和源码变更。

下一步接动态邻居更新、probe/重试定时器及发送调度，再接真正的 ARP 接收与
IPv4/ICMP 入口。公共 capability 仍仅为 checksum，当前无法提供网络服务。
