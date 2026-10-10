# 首批 Linux 基础代码移植

这一阶段把 Linux 原始的网络校验和、红黑树和定时器队列编译到用户态 `libker`，验证直接复用内核源码的构建边界，并提供后续收发包和协议定时器所需的基础能力。尚未接入 skb、IP/UDP/TCP 协议处理或 DPDK。

## 编译源码和头文件

`cmake/LinuxPort.cmake` 显式列出 `lib/checksum.c`、`lib/rbtree.c`、`lib/timerqueue.c`，编译源文件仍位于固定的 Linux submodule 中，未修改它们。构建时将所需原始头文件按白名单复制到构建目录的 `linux-include`，私有兼容头文件优先于这些头文件。没有把整棵 Linux include 目录暴露给应用。

原始头文件包括 `net/checksum.h`、`asm-generic/checksum.h`、`linux/container_of.h`、`linux/rbtree.h`、`linux/rbtree_augmented.h`、`linux/rbtree_types.h`、`linux/timerqueue.h`、`linux/timerqueue_types.h`，以及 Linux UAPI 的 `asm-generic/errno.h` 和 `errno-base.h`。

配置阶段扫描这些源码和头文件中的 Linux include，未在白名单或兼容目录中的依赖直接阻止配置，避免静默引用宿主机的同名 UAPI 头文件。扫描也包含条件编译分支，当前有意采用保守策略。

Linux 代码使用 GNU C 扩展，checksum 还通过整数指针访问包缓冲区，因此内部编译使用 `-fno-strict-aliasing`。仅对上游源文件关闭 unused parameter 警告，因为它们包含空的回调实现；自有源文件仍可使用 `-Wall -Wextra -Werror`。原始头文件作为 system include 处理。

## 私有兼容层

| 接口 | 已实现边界 |
| --- | --- |
| types 与 compiler | 本批源码使用的固定宽度整数、checksum 类型、注解和编译器操作 |
| byteorder 与 bitops | 本机字节序识别、32 位循环右移；checksum 公共结果为网络字节序 |
| container_of 与 build_bug | 使用原始 container_of，保留编译期成员类型检查 |
| READ_ONCE 与 WRITE_ONCE | 所需标量的 relaxed 原子访问，不能让整棵树的并发修改变得安全 |
| rcu_assign_pointer 与 rcu_dereference_raw | release 发布和 acquire 读取指针；没有实现读侧临界区、宽限期或回收 |
| EXPORT_SYMBOL | 不生成内核模块导出表；库符号通过独立的用户态链接规则管理 |
| WARN_ON_ONCE | 本批队列不变量失败时输出位置并 abort，release 构建也不会继续操作损坏的队列 |
| copy_from_user 与 copy_to_user | 只有声明；调用会产生未实现符号并阻止链接，没有伪装成成功的内存复制 |

所有上游非静态实现通过 assembler linkage 声明获得 `ker_linux_` 前缀，而不是宏替换函数名。宏替换会错误触发 checksum 中的 `#ifndef ip_fast_csum` 等架构覆盖检查，跳过本来需要编译的函数。动态库只导出公共 `ker_*` API，Linux 符号和内部 runtime 隐藏。

此兼容层只覆盖本批源码。尚不支持的宏、类型和运行接口应在编译或链接时暴露问题，不能把这些头文件视为完整内核兼容环境。

## 校验和 API

`ker_inet_checksum` 调用 Linux 的 `ip_compute_csum`，`ker_ipv4_transport_checksum` 调用 `csum_partial` 与 `csum_tcpudp_magic`。调用者提供连续包缓冲区，支持非对齐地址和奇数长度。

API 返回零表示成功，失败返回负 errno，并保持输出值不变。输出为网络字节序：写入报文使用 `memcpy`，不能再调用 `htons`。生成时需要先清零 checksum 字段，验证包含 checksum 字段的完整报文应得到零。IPv4 transport 接口接受四字节源地址和目的地址、协议号以及完整 transport segment，其长度上限为 65535。

这些是校验和原语，不进行 IPv4/UDP/TCP 包格式验证。UDP 若计算结果为零，调用者必须按协议语义写入 `0xffff`；是否允许省略 UDP checksum 由之后的协议代码决定。

## 单线程定时器运行环境

`src/runtime/timer.h` 是私有接口，不安装到公共 API。每个 runtime 拥有一棵原始 Linux timerqueue，同一 runtime 及其 timer 的所有操作必须在所属 worker 线程中完成。

timer 必须先初始化，入队后不能移动或复制，释放前必须取消。`ker_timer_arm` 支持添加与重设；将仍在队列中的 timer 移到其他 runtime 返回 `-EXDEV`。`ker_timer_cancel` 可重复调用。

`ker_runtime_poll` 接收单调递增的纳秒时间和回调预算。时间倒退返回 `-EINVAL`，递归轮询返回 `-EBUSY`。到期 timer 先移出队列，再执行回调，回调可取消其他 timer、重设自身或释放自身。重复重设到当前时间的 timer 也受预算限制。相同到期时间的 timer 不承诺回调顺序。

`ker_monotonic_ns` 提供 CLOCK_MONOTONIC 时间。测试可以直接推进显式时间而无需 sleep。`ker_runtime_next_deadline` 供后续 worker 选择轮询或等待策略；cleanup 取消所有待执行 timer 而不调用回调。runtime 尚未提供 Linux timer_list、jiffies、hrtimer、调度器或 softirq 接口。

## 验证

```sh
cmake -S . -B build-port -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-Wall -Wextra -Werror'
cmake --build build-port
ctest --test-dir build-port --output-on-failure

cmake -S . -B build-sanitize -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build build-sanitize
ctest --test-dir build-sanitize --output-on-failure
```

checksum 测试使用独立的逐字节参考实现，覆盖已知报文、IPv4 头、UDP 报文生成与验证、八种地址偏移、奇偶长度、全零与全一数据、随机数据、初始累加值溢出、分段合并、pseudo-header 和参数错误。timer 测试覆盖 511 个 timer 的插入、取消与重设，在操作后检查父指针、根节点颜色、红节点子节点颜色、黑高与队列排序；同时验证预算、回调重设、回调释放自身、取消其他 timer、跨 runtime 拒绝和时钟推进。

已在本机 x86_64 Linux 验证 GCC 静态 Debug 和动态 Release 构建、Clang ASan/UBSan，以及外部应用的安装后链接。大端分支和其他 CPU 架构尚未运行验证。

## 后续协议代码依赖

对固定 Linux 提交的直接 include 检查显示，下一步不能只增加一个 skbuff 源文件：

| 源文件 | 需要处理的直接依赖 |
| --- | --- |
| `net/core/skbuff.c` | mm、slab、interrupt、netdevice、scatterlist、page_pool、uaccess、用户命名空间与 trace，此外还有多协议辅助接口 |
| `net/ipv4/ip_input.c` | skb、inetdevice、路由与 dst、协议注册、netfilter、xfrm 和统计 |
| `net/ipv4/udp.c` | socket、skb、内存页、timer、命名空间、路由、BPF、GRO 与复用端口 |
| `net/socket.c` | file、poll、VFS、wait、任务上下文、uaccess、security 与 syscall 层 |

这只是源码直接依赖清单，不是经过最小 Kconfig 预处理后的完整链接清单。后续先明确 skb 的线性缓冲区、引用计数、clone、headroom、扩容与释放语义，再实现内存分配和必要的页接口。暂不实现的内核设施需要通过配置或显式移植边界排除，保留的问题必须产生可见的编译或链接错误。
