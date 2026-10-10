# DPDK 内存与 skb 所有权

ker 的生产内存后端使用 DPDK 管理分配、NUMA 和包所有权。本阶段增加 DPDK heap 与对象池适配、原生 mbuf 的 clone/COW 验证，并直接编译 Linux 的 `lib/refcount.c`。没有用自定义结构替代 Linux `sk_buff`；后续已接入原始 skb 的线性子集，详见 [Linux skb 线性子集](linux-skb.md)。

## 内存接口和归还路径

| 对象 | 分配 | 归还 | 当前边界 |
| --- | --- | --- | --- |
| 控制对象和可变长度状态 | `rte_malloc_socket` | `rte_free` | 只接受允许阻塞的 GFP_KERNEL，遵守选择的 NUMA socket 和 cache line 对齐 |
| 原子上下文中的变长小对象 | 配置好的 DPDK 尺寸分级 mempool | kfree 按来源归还原池 | GFP_ATOMIC/NOWAIT，独立容量与每核缓存，耗尽无 heap 或跨尺寸回退 |
| 固定大小的描述符 | `rte_mempool_create` 预分配，generic get 获取 | generic put 归还原池 | 支持 GFP_ATOMIC/NOWAIT；池耗尽返回 NULL，没有 heap fallback |
| 包描述符及包数据 | `rte_pktmbuf_pool_create` 与 `rte_pktmbuf_alloc` | `rte_pktmbuf_free` | 使用原生 mbuf，引用计数和 indirect attachment 由 DPDK 维护 |

`src/compat/include/linux/slab.h` 提供有限的私有 kmalloc、kcalloc、krealloc、ksize 与 kmem_cache 入口。控制分配前置元数据记录原始 DPDK allocation base，kfree 将这个 base 归还给 DPDK。固定 kmem_cache 对象记录来源 cache，必须由 kmem_cache_free 归还；尺寸池的 kmalloc 对象则由 kfree 归还，不能混用释放入口。

kmalloc 不用作包 payload 的生产分配路径。后续 skb head 分配需要专门接到 mbuf backing，并保留 Linux 所需的 headroom 和 shared info 布局。DMA 的地址与 IOVA 必须来自 DPDK backing，不能根据普通虚拟地址猜测。

当前没有 libc 分配后端。关闭 `KER_WITH_DPDK` 会移除内存与包适配实现，而不是换成 malloc。

## 初始化与 NUMA

应用或未来 ker runtime 必须先成功初始化 EAL，再由所属 EAL worker 调用私有 `ker_memory_init(socket_id, cache_objects)`。socket 可以是已存在的 NUMA socket 或 SOCKET_ID_ANY，选择保存在调用线程的上下文中。当前仅支持 primary 进程。

控制对象可以使用 DPDK heap 的阻塞分配；本地事件被屏蔽时不允许这种分配。固定 cache 在创建时预分配全部对象，分配和回收只访问 mempool，不扩容。初始描述符 cache 使用零容量的 per lcore cache，便于验证池耗尽与归还；packet pool 可以显式配置 DPDK cache size。

对象与包池操作面向 EAL worker，不允许信号处理器重入同一池。当前没有为任意外部线程提供 user mempool cache，也没有验证多 worker 数据路径。关闭之前需要停止使用者并归还全部对象和 mbuf；描述符 cache 有在用对象时不能销毁，packet pool cleanup 返回 EBUSY。控制内存或尺寸池仍有存活分配时，memory shutdown 返回 EBUSY。

## 原子分配尺寸池

EAL worker 调用 `ker_memory_init` 后、开始轮询前，可用私有
`ker_memory_atomic_pools_init(name, classes, count)` 配置最多八个尺寸池。
每项 `ker_memory_pool_config` 分别指定 `size`、`objects` 和 `cache_size`。
尺寸须按升序排列且为 cache line 的整数倍。池使用该 worker 初始化时选择的
NUMA socket；名称包含 lcore id，创建任何一项失败都会撤销已创建的池。
没有默认容量或运行时扩容，应用/runtime 必须根据业务设置容量。

例如 `{64, 1023, 32}` 与 `{256, 4095, 64}` 分别预留两个尺寸的对象。
这些数值只是配置示例，不是推荐容量；非 64 字节 cache line 的平台需要调整尺寸。
计数还须满足 DPDK 的 mempool cache 约束。

`kmalloc/kzalloc/kcalloc` 的 GFP_ATOMIC/NOWAIT 分配选最小可容纳请求的池。
即使更大的池还有对象，选中池耗尽也返回 NULL；未配置池、请求超出最大尺寸
或不支持的 GFP 标志同样失败。GFP_KERNEL 仍使用 DPDK heap，本地事件屏蔽时
不允许该 heap 路径。两条路径均无 libc fallback，也不宣称实现内核 reclaim。

分配头记录实际来源与容量，`ksize` 返回完整可用容量；尺寸池容量可能大于
`kmalloc_size_roundup` 的 cache-line 下界。kfree 可由另一个已注册且调用过
`ker_memory_init` 的 worker 执行：所属 worker 使用 DPDK 每核缓存，其他 worker
直接归还公共 ring，避免对象滞留在随后注销的线程缓存中。任意未注册线程、
信号处理器重入、worker 注销后继续使用初始化上下文均不受支持。

`krealloc` 在容量内保留原对象；增长使用调用者 GFP 指定的后端，失败时保留
原指针、数据与所有权。`__GFP_ZERO` 清零新的可用容量，增长时保留原请求范围。
原子池和 heap 之间的迁移仍按原来源释放旧对象。

`ker_memory_atomic_pool_stats` 由所属 worker读取各尺寸的配置对象数、在用数、
匹配请求数和失败数；超尺寸及无效标志请求不计入某个尺寸的统计。每核缓存
中的空闲对象属于配置容量，不能把公共 ring 空闲量当成全部可用对象。

关停仍采用保守的全局静止条件：停止所有使用者，等待跨 worker 归还完成，
销毁固定 cache 并归还所有控制对象，之后调用 `ker_memory_shutdown` 回收
当前 worker 的尺寸池。全局仍有存活分配时返回 EBUSY。所属 worker 必须在
shutdown 成功后才注销或退出，因为归还路径会访问其池记录。
这不是各 worker 独立在线销毁，也不是 RCU 延迟回收。

本阶段验证了真实 EAL 下的尺寸池创建回滚、独立耗尽、清零、realloc 失败回滚
以及已注册 pthread 的跨 worker 归还。尚未验证多 NUMA 压力和吞吐；socket
内存记账、连接/请求预算、预留控制资源、水位背压及 TCP 长期持有数据仍待实现。

## 每 worker 分类容量预算

`ker_memory_budget_configure` 在全体分配与归还使用者静止、全局存活分配为零时
配置所属 worker 的 CONTROL、CACHE、ATOMIC 三类额度。CONTROL 包含 DPDK heap
控制对象（也包含 kmem_cache 描述符），CACHE 包含固定 cache 对象，ATOMIC
包含通用原子尺寸池对象。默认额度为零表示不设硬上限，并保留容量统计。
一个 worker 的某类额度耗尽不会借用其他类别或其他 worker 的额度。

额度按 `ksize` 的可用容量计费，不按请求字节数。尺寸池分配 65 字节若命中
256 字节池，就计 256 字节。分配前先原子预留；预算不足返回 NULL，底层池
耗尽、heap 失败或故障注入时撤销预留。增长 realloc 保留旧对象直到新对象
分配成功，因此需要容纳两份对象的短期容量；失败时原对象及其计费不变。
原地调整请求长度不会改变容量计费。跨后端增长按新对象的类别重新计费，
释放旧对象时扣回原类别。

每类可设置硬上限 `limit`、高水位 `high` 和低水位 `low`。到达 high 时进入
压力状态，只有回落到 low 或以下才退出，避免在一个阈值附近反复切换。
high 为零关闭压力状态；limit 为零仅取消硬上限，也可以继续设置水位。
容量与压力位由同一个 CAS 更新，跨 worker 并发归还不会用旧容量计算出的
压力状态覆盖新容量的状态。配置值不能使用 size_t 的最高位；非零 high
须高于 low，设置硬上限时 high 不得超过 limit。

`ker_memory_budget_stats` 返回当前预留/在用容量、峰值预留、预算拒绝次数
和压力状态。峰值可能包含随后因后端失败而撤销的预留；预算拒绝计数不包含
底层分配失败、超尺寸或不支持的 GFP 请求。各统计字段不是整体原子快照。
预算记录保存在原分配 worker，分配头记录其来源；其他 worker 释放时扣回
原 worker，不计入归还 worker 的额度。固定 cache 对象按分配者而非建池者计费。

这些额度限制逻辑上的活跃容量，**不是 DPDK 物理内存总量上限**：mempool
在初始化时已预分配，空闲对象、分配头、ring/cache 元数据及对齐开销不在
这些在用容量计数中。mbuf 数据仍由各 packet pool 的对象数和 data room
限制，未计入这三类预算；不能据此宣称已经实现 socket/TCP 内存记账。

压力状态已由私有 [worker 轮询框架](worker.md) 接入 RX 门控；内存层自身不会阻塞分配线程、
回收连接或修改 TCP 窗口。连接/请求级额度、全进程及 NUMA 总预算、控制报文
资源预留仍待接入。关停仍要求停止所有使用者、全部归还后由所属 worker
shutdown 成功再退出；预算记录的 TLS 生命周期与尺寸池采用相同规则。

真实 EAL 测试覆盖类别隔离、实际容量计费、硬上限与双水位、失败预留回滚、
realloc 峰值需求和跨后端迁移，以及三个注册 worker 并发归还到原 worker。

## 引用计数与锁

直接编译原始 `lib/refcount.c`，并导入原始 `refcount.h`、`refcount_types.h` 和 `gfp_types.h`。私有 atomic 操作保留 relaxed、release、acquire 语义；使用 `-fwrapv` 保留原始饱和检测中的整数回绕行为。溢出和错误引用操作保留上游饱和处理与告警，避免计数回绕为零后释放对象。

mutex 使用 pthread mutex，spinlock 使用真实的 acquire/release 原子锁。本地 irqsave 在用户态的含义是屏蔽当前线程的 ker 事件回调，timer poll 在被屏蔽时返回 EBUSY；它不关闭硬件 IRQ，也不屏蔽 POSIX 信号。完整 softirq、任务调度和 RCU 宽限期仍未实现。

未来 Linux skb 的 `users` 继续使用原始 refcount，`skb_shared_info.dataref` 必须保留 Linux 自己的共享数据与 header 引用语义。DPDK 的 mbuf refcount 不能直接替换这个字段。线性 skb bridge 已让一份 Linux backing 拥有一个 mbuf 引用，由最终 backing 释放路径归还它。本阶段的 native mbuf clone/COW 只是验证 DPDK 包所有权。

## 原生 mbuf 和 COW

`ker_packet_alloc` 从 packet pool 获取原生 mbuf；`ker_packet_clone` 调用 DPDK 的 clone 接口，得到共享 backing 的 indirect mbuf。所有释放通过 `rte_pktmbuf_free` 完成，不能直接释放其 buf_addr。

`ker_packet_make_writable` 对唯一 direct mbuf 无需复制。对于 indirect mbuf 或有多个描述符引用的 direct mbuf，调用 DPDK 的 copy 接口，保留包元数据，校验目标容量后调整 data offset 并复制已 pull 到 headroom 的头部，最后释放调用者持有的旧引用。失败时保留旧指针及其引用，不会半途转移所有权。copy、clone 和分配都只使用指定池。

当前只处理单 segment，COW 不支持 external backing 或链式 mbuf，明确返回 ENOTSUP。没有实现 mbuf 与 skb 的零拷贝适配、TX offload 配置或 PMD 收发。

## 构建与验证

`tools/build-dpdk.sh` 编译和本地安装固定 submodule 的 DPDK，启用基础库及 ring mempool 驱动。默认安装到 `third_party/dpdk/install/lib64`，CMake 不会静默使用宿主机的旧版 DPDK。`KER_DPDK_DRIVERS` 可显式调整驱动列表，`KER_DPDK_JOBS` 可调整构建并发度；未来验证网卡时再启用所需 PMD。

测试在真实 EAL 下选择进程允许的 CPU，以 logical lcore 0 运行，使用 no huge、no PCI、no shared config 和 VA IOVA 模式，无需网卡或 root。验证内容包括：

- DPDK heap 对齐、零初始化、容量、溢出拒绝、故障注入和 realloc 回滚。
- 七个对象的固定 mempool 在 GFP_ATOMIC 下分配，耗尽失败、归还后再分配与最终全部回收。
- 七个 mbuf 的池耗尽、clone 的共享引用、COW 失败保留原对象、COW 后内容隔离、headroom 和 VLAN 元数据，以及 direct descriptor 共享引用的分离。
- 关闭存活池的拒绝、unsupported segment 的所有权不变、跨池 indirect mbuf 保留原 backing，以及目标容量不足时临时 segment 的完整归还。
- 原始 refcount 的正常与饱和行为、四个 pthread 的引用操作和锁竞争、本地事件屏蔽与 timer 恢复。

已验证 GCC Debug 静态库、Release 动态库，以及 Clang ASan/UBSan。DPDK 本身未启用 sanitizer，故障注入也只覆盖 ker 的控制分配入口；这些检查不代表 DPDK 池内部所有边界或真实 NIC DMA 已验证。NUMA API 已接入，尚未运行跨 NUMA 性能测试。
