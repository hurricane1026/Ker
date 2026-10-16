# ker 用户态网络栈

ker 的目标是把 Linux kernel 网络栈移植到用户态，以 DPDK 提供网卡收发和运行基础，向上层应用提供 C API。当前实现的是 Linux 网络基础代码的兼容层、DPDK 内存和队列适配，以及无状态 Ethernet/IP/ICMP/UDP/TCP 报文 view 与构造器；TCP/UDP socket 和连接语义尚未由导入的 Linux 实现提供，因此当前不能独立提供网络服务。

目前已移植 checksum、rbtree、timerqueue 和 refcount 基础代码，并接入 DPDK heap、原子分配尺寸池、每 worker 分类容量预算、描述符 mempool、原生 mbuf 生命周期及 Linux 原始 skb 的线性子集，以及按容量压力限制 RX 的私有 worker 轮询框架，以及原始 net_device 布局、Ethernet 接收分类、单 worker NAPI 调度/完成、原始 packet_type 协议匹配/投递、ARP/Ethernet 报文构造、原始 IPv4 静态地址视图、固定容量永久邻居表，以及原始 ARP 接收门控和私有消息回调，以及按包数/truesize 限制的原始 skb FIFO。提供公共校验和 API，其他 runtime 与内存接口仍是私有接口。**完整 skb、IP/UDP/TCP 协议层、网卡收发和 socket API 尚未实现，当前不能提供网络服务。** `ker_capabilities()` 仍返回 `KER_CAP_CHECKSUM`（`0x20`），协议栈和网卡能力仍关闭。

现有 flow steering 仅解析 TCP/UDP 报文头并选择包的调度 worker；它不实现协议栈或连接状态。边界见[固定 flow steering](docs/flow-steering.md)。

## 获取依赖

```sh
git submodule update --init --recursive --depth 1
```

依赖位于 `third_party/linux` 和 `third_party/dpdk`，来自 `hurricane1026` 的 GitHub fork。主仓库通过 gitlink 固定具体提交；日常构建不要使用 `git submodule update --remote`。初始提交取自 fork 的默认分支，尚未验证为可移植的版本组合。

| 依赖 | 源码声明版本 | 固定提交 |
| --- | --- | --- |
| Linux | 7.3.0 rc6 | `3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0` |
| DPDK | 26.11.0 rc0 | `d129414711aa7c4954f997acf4c54338574a7d92` |

版本字段来自各自源码；这两个提交均属于开发版本。进入协议栈移植阶段前，应评估是否改用 fork 内的稳定版本作为长期基线。

## 编译 DPDK 与 ker

DPDK 模式下的线性 skb 当前限定为 64 位小端目标，已运行验证的平台为 x86_64 Linux。

当前支持 Linux 主机上的 GCC 或 Clang，需要 GNU C 扩展、CMake 3.20 或更新版本，以及 Python 3、Meson、Ninja、pkg-config 和 DPDK 构建所需的开发依赖。构建需要初始化两个 submodule，不需要生成内核头文件。最小 DPDK 配置只启用 ring mempool 驱动，用于内存移植验证。

```sh
bash tools/build-dpdk.sh
export PKG_CONFIG_PATH="$PWD/third_party/dpdk/install/lib64/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH="$PWD/third_party/dpdk/install/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cmake -S . -B build
cmake --build build
./build/ker-info
./build/ker-checksum
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/build/install"
```

DPDK 默认启用，从 fork 的本地安装目录查找，要求版本至少为 26.11.0。其他安装位置可通过 `-DKER_DPDK_PKGCONFIG_DIR=/path/to/pkgconfig` 显式指定。`-DKER_WITH_DPDK=OFF` 只编译基础代码，不提供内存或包后端，也不回退到 libc。DPDK 测试在真实 EAL 中使用 `--no-huge --no-pci --no-shconf`，不要求 root、网卡或 hugepage。

默认生成静态库；`-DBUILD_SHARED_LIBS=ON` 生成动态库。已安装的库可通过 `find_package(ker CONFIG REQUIRED)` 和 `target_link_libraries(app PRIVATE ker::ker)` 使用；DPDK 模式下外部应用也需要正确的 pkg-config 和动态库搜索路径。`<ker/ker.h>` 提供版本和能力查询，`<ker/checksum.h>` 提供 Internet checksum 与 IPv4 transport pseudo-header checksum。结果为网络字节序，可以用 `memcpy` 写入包头，无需 `htons`。测试默认开启，可用 `-DBUILD_TESTING=OFF` 关闭。

## 工程布局

| 路径 | 职责 |
| --- | --- |
| `include/ker` | 上层应用使用的公共 API，不暴露 Linux 或 DPDK 内部类型 |
| `src/compat` | 私有 Linux 兼容头文件和符号隔离声明 |
| `src/runtime` | 定时器、事件屏蔽、DPDK 内存、mbuf 与线性 skb 接入 |
| `tests` | 校验和、定时器、refcount、锁与真实 EAL 内存生命周期测试 |
| `tools` | 固定 fork 的 DPDK 构建脚本 |
| `examples` | 公共 API 示例 |
| `cmake` | 安装后供应用查找的 CMake 配置 |
| `third_party/linux` | Linux fork，以 submodule 管理 |
| `third_party/dpdk` | DPDK fork，以 submodule 管理 |
| `docs/architecture.md` | 移植边界、运行模型与分阶段验收标准 |

移植边界见 [Linux 基础代码移植](docs/linux-port.md)、[DPDK 内存与 skb 所有权](docs/dpdk-memory.md) 和 [Linux skb 线性子集](docs/linux-skb.md)。下一阶段接入原始 ARP/IPv4 入口及邻居和发送路径，并补齐设备注册、连接预算与独立控制资源。Ethernet 边界见 [原始接收分类](docs/linux-ethernet.md)。NAPI 边界见 [调度与完成](docs/linux-napi.md)。协议投递边界见 [匹配与所有权](docs/linux-receive.md)。ARP 构造边界见 [报文与导出](docs/linux-arp.md)。ARP 接收边界见 [门控与消息回调](docs/linux-arp-receive.md)。地址边界见 [静态 IPv4 配置](docs/linux-ipv4-address.md)。邻居边界见 [永久表与引用](docs/linux-neighbor.md)。待发送队列见 [原始 FIFO 与限额](docs/linux-skb-queue.md)。Worker 边界见 [轮询与 RX 压力](docs/worker.md)，flow 选择边界见[固定 flow steering](docs/flow-steering.md)。整体路线见[架构与移植路线](docs/architecture.md)。

The private [Linux timer_list adapter](docs/linux-timer-list.md) associates unchanged
native timer fields with worker timerqueues, including scoped jiffies, bounded
callback delivery, shutdown, and lifetime guards.

The private neighbor adapter also accepts explicit offline timing and probe
parameters through verbatim Linux setters and reachable-time randomization;
this does not enable dynamic neighbor resolution yet.

The private [neighbor timer monitor](docs/linux-neighbor-timer.md) runs the
original Linux reachability and retry handler for configured IPv4/MAC mappings,
with copied probe/notification callbacks and explicit lifecycle pins. During a
native probe callback, the bounded [ARP probe adapter](docs/linux-arp-probes.md)
can return Linux's constructed packet as a caller-owned skb. NIC transmission,
ARP learning and unresolved packet queues remain unsupported.

ICMPv4 通用报文和控制服务边界见 [ICMPv4 控制层](docs/linux-icmpv4-control.md)。该服务不实现 socket 错误队列或 PMTU policy/cache；socket、路由与 IPv4 重组仍未接入。

F-Stack 外部测试场景的适配范围与追溯见 [测试迁移](docs/fstack-tests.md)，每个适配场景独立运行真实 DPDK 回归测试。
借用现有 DPDK ethdev TX 队列的生命周期与所有权约束见 [ethdev TX adapter](docs/dpdk-ethdev-tx.md)。
借用现有 DPDK ethdev RX 队列并接入 Ker Ethernet 分类/接收分发的边界见 [ethdev RX adapter](docs/dpdk-ethdev-rx.md)。
