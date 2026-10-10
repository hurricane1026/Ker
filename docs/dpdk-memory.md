# DPDK 内存与 skb 所有权

ker 的生产内存后端使用 DPDK 管理分配、NUMA 和包所有权。本阶段增加 DPDK heap 与对象池适配、原生 mbuf 的 clone/COW 验证，并直接编译 Linux 的 `lib/refcount.c`。没有用自定义结构替代 Linux `sk_buff`；原始 skb 的编译和接入仍是下一阶段工作。

## 内存接口和归还路径

| 对象 | 分配 | 归还 | 当前边界 |
| --- | --- | --- | --- |
| 控制对象和可变长度状态 | `rte_malloc_socket` | `rte_free` | 只接受允许阻塞的 GFP_KERNEL，遵守选择的 NUMA socket 和 cache line 对齐 |
| 固定大小的描述符 | `rte_mempool_create` 预分配，generic get 获取 | generic put 归还原池 | 支持 GFP_ATOMIC/NOWAIT；池耗尽返回 NULL，没有 heap fallback |
| 包描述符及包数据 | `rte_pktmbuf_pool_create` 与 `rte_pktmbuf_alloc` | `rte_pktmbuf_free` | 使用原生 mbuf，引用计数和 indirect attachment 由 DPDK 维护 |

`src/compat/include/linux/slab.h` 提供有限的私有 kmalloc、kcalloc、krealloc、ksize 与 kmem_cache 入口。控制分配前置元数据记录原始 DPDK allocation base，kfree 将这个 base 归还给 DPDK。对象池元数据记录来源 cache，不能把池对象交给 kfree，或归还到其他池。

kmalloc 不用作包 payload 的生产分配路径。后续 skb head 分配需要专门接到 mbuf backing，并保留 Linux 所需的 headroom 和 shared info 布局。DMA 的地址与 IOVA 必须来自 DPDK backing，不能根据普通虚拟地址猜测。

当前没有 libc 分配后端。关闭 `KER_WITH_DPDK` 会移除内存与包适配实现，而不是换成 malloc。

## 初始化与 NUMA

应用或未来 ker runtime 必须先成功初始化 EAL，再由所属 EAL worker 调用私有 `ker_memory_init(socket_id, cache_objects)`。socket 可以是已存在的 NUMA socket 或 SOCKET_ID_ANY，选择保存在调用线程的上下文中。当前仅支持 primary 进程。

控制对象可以使用 DPDK heap 的阻塞分配；本地事件被屏蔽时不允许这种分配。固定 cache 在创建时预分配全部对象，分配和回收只访问 mempool，不扩容。初始描述符 cache 使用零容量的 per lcore cache，便于验证池耗尽与归还；packet pool 可以显式配置 DPDK cache size。

对象与包池操作面向 EAL worker，不允许信号处理器重入同一池。当前没有为任意外部线程提供 user mempool cache，也没有验证多 worker 数据路径。关闭之前需要停止使用者并归还全部对象和 mbuf；描述符 cache 有在用对象时不能销毁，packet pool cleanup 返回 EBUSY。控制内存还有存活分配时，memory shutdown 返回 EBUSY。

## 引用计数与锁

直接编译原始 `lib/refcount.c`，并导入原始 `refcount.h`、`refcount_types.h` 和 `gfp_types.h`。私有 atomic 操作保留 relaxed、release、acquire 语义；使用 `-fwrapv` 保留原始饱和检测中的整数回绕行为。溢出和错误引用操作保留上游饱和处理与告警，避免计数回绕为零后释放对象。

mutex 使用 pthread mutex，spinlock 使用真实的 acquire/release 原子锁。本地 irqsave 在用户态的含义是屏蔽当前线程的 ker 事件回调，timer poll 在被屏蔽时返回 EBUSY；它不关闭硬件 IRQ，也不屏蔽 POSIX 信号。完整 softirq、任务调度和 RCU 宽限期仍未实现。

未来 Linux skb 的 `users` 继续使用原始 refcount，`skb_shared_info.dataref` 必须保留 Linux 自己的共享数据与 header 引用语义。DPDK 的 mbuf refcount 不能直接替换这个字段。拟定的 bridge 是让一份 Linux backing 拥有一个 mbuf 引用，由最终 backing 释放路径归还它；这部分尚未接入。本阶段的 native mbuf clone/COW 只是验证 DPDK 包所有权。

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
