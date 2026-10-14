# IPv4 单播 UDP 代理适配

本轮交付目标是为应用层代理提供有界、归属明确的 UDP datagram 接口。
这些接口位于 Ker runtime adaptation layer；不修改 Linux 或 DPDK 上游文件，
也不把它们声明为完整 BSD socket API。

## 对象与归属

每个 worker 使用自己的 packet pool、skb context、device、receive runtime、
endpoint table 和 UDP I/O 对象。端点句柄包含表身份、槽位和 generation；
关闭后重绑端口不会使旧句柄指向新端点。connect/disconnect 另推进 incarnation，
用于区分同一端点的不同连接时期。应用必须在对象的 owner worker 调用 API，
并在释放对象存储前完成清理。

下游监听端点接收 datagram 时复制负载及源地址/端口到应用提供的有界槽位。
应用读取后，根据自己的会话规则找到上游 channel，再发送到显式注册的 peer。
UDP 本身没有连接握手；应用的请求、响应关联、会话超时和重试策略仍由应用定义。
connect 仅指定默认发送目标和完整源 tuple 的接收过滤。
generation 保护应用句柄，不出现在 UDP wire header 中。同一 tuple 关闭后立即
复用，迟到的普通 UDP 响应仍可能被新 channel 接收；应用需要协议级关联标识或
端口复用等待策略，不能把句柄代次当成 UDP 报文的防重放标识。

## 上游端口与响应分流

`ker_udp_channel_open_owned` 在调用方指定的闭区间端口范围内查询完整 tuple：
domain、IPv4、UDP、本地 IP/端口和上游 IP/端口。它使用 `ker_flow_owner`，
因此遵循相同的 hash、bucket 和 special mapping。只有 owner 等于当前 worker
且端口未被占用时才创建并连接 channel。

响应必须以同一 domain 和 `KER_FLOW_INGRESS` 进入同一个 immutable fabric，
这样解析得到的本地/远端字段与选择端口时一致。该方法不需要向 shard 0 查询，
不修改共享映射，也不迁移运行中的状态。若没有任何 tuple 属于当前 worker，
返回 `-EADDRNOTAVAIL`；属于当前 worker 的端口全部已绑定时返回 `-EADDRINUSE`。
端口范围扫描有明确上限，65535 是有效的最后一个候选端口。

该保证仅针对创建时的完整 tuple。上游目标 IP 或端口改变时，应用应关闭 channel
并重新调用 `open_owned` 选择端口；不能直接在该 channel 上 reconnect 或对另一个
目标 sendto 后继续假设响应 owner 不变。通用 UDP API 保留显式 sendto 的能力，
不保存 flow context，也不会替应用执行这条组合约束。

ICMPv4 Destination Unreachable、Time Exceeded 和 Parameter Problem 的 ingress
分流使用其引用的原始 UDP tuple，而非报告错误的路由器地址。因此错误通知也能
到达发送 channel 的 owner。该分流只接受本轮无 options、无分片的 IPv4 UDP
profile，并要求至少有完整引用 UDP header；不会把缺失字段当成零端口。
分流本身不验证 checksum 或认可错误真实性，owner 上的接收校验和实际发送证据
检查仍必须通过，才允许交付错误或更新 PMTU。Echo、Redirect 和引用 TCP 的
ICMP 报文不走此 UDP 错误分流路径。

下游监听端口可在不同 worker 的独立端点表分别绑定；每个 datagram 只由 fabric
选中的 owner 处理。这不是同一端点表上的 SO_REUSEPORT 实现。应用保持每个下游
tuple 的会话状态在该 owner，并为上游选择同 owner 的端口。

ARP 属于独立控制路径，不能交给只解析 IP flow 的 fabric 后期待其自动分流。
部署需将 ARP 回复交付给对应邻居 monitor 所在的 worker。双 CPU 集成测试中，
客户端和上游服务共享一端的 IPv4 地址、使用不同 UDP 端口；代理运行在另一
固定 CPU，并使用独立 pool/context。测试显式交付 ARP 控制报文，验证首次解析
和排队 flush，不宣称已实现多代理 worker 的通用 ARP 分发。

## 背压与资源预算

每个接收 channel 的 datagram 数量、槽位长度和总字节数由调用方限定。
超出槽位长度的负载保留前缀，并报告原始长度及截断；包数或字节预算耗尽时丢弃
并计数。零长度 datagram 仍是一次成功接收，不能与空队列混淆。

应用层代理必须决定如何处理接收截断。透明转发应拒绝截断报文，不能将前缀当成
完整应用请求。发送成功表示本地路径接受，不能据此断言对端已接收。ARP 排队、
TX 队列及 ring 均有上限；UDP 不保证交付，也不会因本地重试获得端到端可靠性。

## 集成验证

双 CPU 测试从实际被 TX sink 接受的 600 字节上游 UDP 报文截取引用，构造有效
ICMP Fragmentation Needed，经 flow inbox 转发至代理 owner。测试检查 channel
错误队列中的 tuple、类型/code 和有效 MTU 576，并验证后续同尺寸发送返回
`-EMSGSIZE`。这条路径同时覆盖引用分流、接收校验、发送证据关联和 PMTU 执行。

## 本轮边界

仅支持已配置本地 IPv4 地址与显式注册的单播 peer。没有通用路由表、IPv6、
广播/多播、IPv4 分片重组、完整 socket/epoll 兼容或真实网卡 offload。
测试使用真实 EAL、packet pool、Linux checksum 和有界 DPDK ring，不能将这些
结果解释成 NIC/RSS 互通或完整 F-Stack/FreeBSD 栈一致性。

For independent Linux UDP socket validation, see [UDP host interoperability](udp-host-interop.md).
