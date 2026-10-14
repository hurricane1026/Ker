# ker 架构与移植路线

ker 的目标是将 Linux 网络协议代码编译进用户态库，并通过 DPDK 驱动网卡。当前已编译原始 checksum、rbtree、timerqueue 与 refcount，建立定时器运行环境，并接入 DPDK heap、描述符 mempool 和原生 mbuf 生命周期；原始 skb 的线性子集也已接入；协议数据路径仍待实现。第一目标是可验证的单 worker IPv4 和 UDP 收发，再推进 TCP 和多核性能。

## 数据路径和模块边界

```text
HTTP 服务 / WAF / UDP 与 TCP 应用
                 |
        ker 公共 C API 与事件接口
                 |
      移植的 Linux socket 与协议实现
                 |
      sk_buff / net_device / NAPI 适配
                 |
        DPDK mbuf / RX 与 TX queue
                 |
                网卡
```

Linux 使用 `sk_buff` 管理网络包，NAPI 负责网络事件处理；DPDK 使用 `rte_mbuf` 管理包缓冲区。因此 ker 需要在这些接口之间实现包生命周期与事件调度适配，而不是只替换网卡驱动。参考 [Linux sk_buff](https://docs.kernel.org/networking/skbuff.html)、[Linux NAPI](https://docs.kernel.org/networking/napi.html) 和 [DPDK mbuf](https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html)。

公共 API 隐藏 Linux 和 DPDK 类型。HTTP 解析、TLS、WAF 规则和请求策略放在上层应用；ker 提供它们需要的连接、字节流、报文和事件能力。后续 socket API 使用独立的 ker 句柄，明确线程归属和错误约定，不直接假定它们是宿主机文件描述符。

## Linux 用户态运行环境

先对固定提交的 `net/core`、`net/ethernet`、`net/ipv4`、socket 层和所需 `lib` 代码做编译与链接依赖清单。明确每个源文件、配置符号、生成头文件以及未解析符号；不能把整个 `net/` 目录直接加入普通 CMake 目标就视为完成移植。

| 依赖 | 拟实现的用户态语义 |
| --- | --- |
| 内存与 slab | 控制对象走 DPDK heap，固定描述符走 mempool，包数据走 mbuf；已有对齐、失败传播、池耗尽和回收验证，已接入原始线性 skb 的独立 users/dataref、clone、COW 和 mbuf 接管，非线性 skb 待实现 |
| per CPU 与 current | worker 绑定的上下文和明确的访问规则 |
| 锁与原子操作 | 已接入原始 refcount，使用原子操作、真实 spinlock 和 pthread mutex；本地事件屏蔽阻止 timer dispatch，尚无完整 softirq |
| RCU | 读侧临界区、宽限期和延迟回收，先明确可验证的单 worker 模型 |
| timer 与时间源 | 已有 CLOCK_MONOTONIC、timerqueue 和 worker-local Linux timer_list 适配，支持调度、取消、重设与预算；原生邻居定时器已接入，hrtimer 和 TCP 重传仍待移植 |
| softirq 与 NAPI | worker 主动运行待处理事件，遵守预算和完成语义 |
| workqueue 与等待机制 | 可显式推进的任务和等待状态，防止阻塞轮询线程 |
| 初始化与网络配置 | 必需子系统的初始化顺序、接口、地址、路由和邻居配置 |

优先通过独立兼容层和受控的配置文件适配。必要的 Linux 源码修改保存在用户的 fork 中，由 ker 更新 submodule 提交引用。禁止将未实现的核心依赖静默伪装成成功；每个依赖必须实现、通过配置排除或明确阻止构建。

## DPDK 收发与包所有权

第一版采用复制路径：接收时把 mbuf 数据复制到 skb，发送时把 skb 数据复制到 mbuf。这能先验证协议行为并明确生命周期；零拷贝放在之后，单独验证引用计数、分段包、headroom、克隆和释放回调。

RX 获取的 mbuf 由适配层负责释放；交给 Linux 的 skb 由协议栈管理。TX burst 接收的 mbuf 交给 DPDK，未被接收的部分仍由 ker 管理，需要重试或释放。所有失败路径必须保持这一边界。先关闭尚未适配的 checksum 和分段 offload，再逐项增加并核对元数据。

## Worker 与应用运行模型

第一阶段在一个线程上运行一个栈实例，按预算轮询 RX、处理协议事件、推进 timer、服务应用事件并提交 TX。即使没有收包，也必须推进定时器。应用回调不能长时间阻塞这个线程。

当前已接受一项有限的多 worker 基线：用固定 seeded tuple hash 和不可变 bucket-to-worker 表确定 TCP/UDP 包的 owner，并通过有界 mbuf inbox 在 worker poll 中交接；适配层还可提供有界 exact-key owner override。详见 [固定 flow steering](flow-steering.md)。方向是每个 worker 持有并访问自己的可变协议与设备状态；现有 Linux 全局状态仍需逐项审计并通过适配层隔离或明确共享，完整的独立 worker 协议栈、RSS、监听与 accept 分发、RCU 和在线路由更新仍待实现和验证。

## 分阶段验收

| 阶段 | 交付 | 验收条件 |
| --- | --- | --- |
| 0 工程基础 | 固定依赖、基础库、公共头文件、安装包 | 已能编译、安装并从外部项目链接 |
| 1 编译入口 | 最小 Linux 配置、依赖清单、兼容层、初始化 | 进行中：四个 Linux 基础源文件已编译，并有 DPDK 内存后端；原始 skb 线性子集已接入，完整 skb、协议源文件、配置和网络初始化仍待实现 |
| 2 单 worker 数据路径 | DPDK 生命周期、虚拟 net_device、复制收发 | 用软件测试设备或测试链路验证 ARP、IPv4、ICMP，覆盖丢包和释放路径 |
| 3 UDP | 地址和路由配置、非阻塞 datagram API | 与宿主机或独立对端互通，检查 checksum、MTU 和分片策略 |
| 4 TCP | 连接与监听 API、事件通知、timer | 验证握手、重传、乱序、窗口、关闭、超时和背压 |
| 5 多核与性能 | 队列分配、连接归属、NUMA、批处理、零拷贝 | 在固定硬件和流量下报告吞吐、延迟分位数、CPU、内存及正确性回归 |
| 6 应用 | HTTP 服务示例、WAF 集成示例 | 验证长连接、慢客户端、请求体限制、解析边界及策略行为 |

## 源码与分发

submodule 的许可证以各自源码声明为准。移植前需要确认所选 Linux 源文件和组合产物的许可证及分发要求，再决定 ker 自有代码与对外 API 的许可证。当前没有为自有代码添加许可证声明。

TCP 控制字段与原生 MSS 解析的当前边界见 [TCP control view](tcp-control.md)。连接、监听和握手状态机仍需后续实现。
