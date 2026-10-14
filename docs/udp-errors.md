# UDP 异步错误与 PMTU

UDP 发送成功只说明本地路径接受了报文。接收 ICMPv4 错误时，不能仅凭远端地址
或端口相同就通知应用或降低 PMTU：该报文可能仍在 ARP 队列中、已被本地丢弃，
或者属于端点关闭前的旧一代。

`ker_udp_error_tracker` 使用调用方提供的有界记录数组。构造 UDP 报文前预留
记录及 IPv4 identification，构造完成后记录原始 IPv4/UDP header 字段。
预留记录处于 RESERVED；只有 TX exporter 的 sink 返回零、接受完整 mbuf 副本
后，才转为 SENT。observer 在调用 sink 前复制所需字节，完成回调不再读取可能
已被 sink 释放的 mbuf。这里的发送证据是应用 sink 的接受，不是 NIC 完成或
对端交付确认。

使用顺序是先创建 tracker 和 UDP I/O，在注册 peer、打开 channel 之前调用
`ker_udp_io_attach_error_tracker`。随后注册的 peer 同时接入错误关联与 PMTU，
每个发送 channel 通过 `ker_udp_channel_attach_errors` 提供自己的错误队列存储。
启用 tracker 后，未配置错误队列的 channel 不能发送，避免产生无法关联的报文。
关闭 channel、注销 peer 后才能拆除 tracker attachment；tracker 仍被 I/O 引用时
不能 cleanup。未选择该可选 attachment 的既有 UDP I/O 行为保持独立。

ICMP 接收链路先完成已有的外层报文、checksum、本地地址及引用字段检查。
observer 再匹配引用的本地/远端地址、端口、IPv4 ID、IP/UDP 长度和 UDP checksum，
并要求端点 generation 与连接 incarnation 仍有效。错误可以由中间路由器报告，
但引用的目标必须对应本 tracker 注册的 peer。没有匹配 SENT 记录的报文不能
通过该 tracker 更新 PMTU 或进入应用错误队列。

错误事件复制到调用方提供的有界队列，包含 errno、ICMP type/code、原始 tuple、
reporter 地址、序号和 MTU 诊断。队列满会计数丢弃；关闭或重连不会让旧连接的
错误进入新连接。Destination Unreachable、Time Exceeded 和 Parameter Problem
提供通知；Redirect 不安装路由。确认的 Fragmentation Needed 通过既有 PMTU
适配器降低 peer 的 MTU，后续发送按该值返回 `-EMSGSIZE`，到期后恢复初始 MTU。

SENT 记录按有界时间窗到期。RESERVED 记录不能仅靠时间删除，因为 ARP/TX
队列中的原报文可能稍后才发送。原生邻居队列发生丢弃或取消后，调用方先排空
所有注册 peer 的 ARP 队列和 TX exporter，再调用 `ker_udp_error_resync` 回收
剩余预留记录。队列未排空时拒绝重置。这条显式恢复路径避免把仍可发送的报文
误当作已取消，但在完成 drain 前可能因记录耗尽拒绝新发送。

IPv4 ID 和引用 header 的匹配不提供密码学认证。有效期之外，完整 wire tuple
及 ID 的复用仍存在网络延迟报文混淆的固有限制；这不是无限期防重放保证。
应用仍需处理 UDP 丢包、重复、乱序、会话超时和业务重试。
