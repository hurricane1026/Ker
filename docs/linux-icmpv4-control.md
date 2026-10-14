# ICMPv4 控制服务与路径 MTU

本层在 Ker 的 worker、接收分派、skb、原生 Linux checksum 和邻居输出之间
实现 ICMPv4 控制逻辑。Linux 与 DPDK 源码保持不变。它扩展了
[echo 服务](linux-icmp-echo-service.md)，没有将依赖 socket、FIB、netns 和
IPv4 reassembly 的整个 Linux `icmp_rcv` / `__icmp_send` 替换成成功 stub。
IPv6、ICMPv6、NDP 和 MLD 不在本轮实现中。

## 报文接口

`icmpv4-packet-view` 校验完整 IPv4/ICMP checksum、长度和 type/code，允许
DF，拒绝外层 reserved flag、MF 和非零 fragment offset。现有 echo view
保留接口，委托通用 view 执行校验。所有 view 都借用输入内存，只能在接收
回调期间读取，不能修改、释放或在回调后保留。

| 消息 | 接口行为 |
| --- | --- |
| Echo 8/0 | 构造、解析；服务可启用自动回复，保留 identifier、sequence 和 payload |
| Destination unreachable 3 | code 0–15；引用报文及 code 4 的 next-hop MTU |
| Time exceeded 11 | code 0–1；引用报文 |
| Parameter problem 12 | code 0–2；pointer 与引用报文 |
| Redirect 5 | code 0–3；gateway 与引用报文；只交付事件，不安装路由 |
| Timestamp 13/14 | 20 字节消息；可启用回复，保留 originate，注入 UTC 毫秒时钟生成 receive/transmit |
| Extended echo 42/43 | RFC 8335 本地接口查询；显式启用，支持名称、索引和 IPv4 地址，回复 TTL 255、DF |
| 其他 type | 返回不支持；不模拟 source quench、旧地址发现或未知控制行为 |

quoted IPv4 view 与完整 IPv4 view 分开：原始 total length 可以大于引用长度，
但 IHL 与最初的有效 payload 字节必须可读。允许引用中的 IPv4 options，
非首片不提供 flow identity。不会要求引用头 checksum 正确，因此不把正常的
截断引用或 parameter-problem 引用误当完整 IP 包校验。RFC 4884 扩展与引用
有独立边界；扩展原始数据可读，不实现各类扩展对象的业务解释或生成。

`icmpv4-create` 构造显式地址消息。error constructor 将引用限制在
`min(path_mtu, 576)` 的 IPv4 消息长度内；所有失败保持输出槽不变。
构造合法报文与决定何时允许发送错误分开，调用者不能用 raw constructor
替代下面的发送策略。

## 服务与错误交付

零初始化 `ker_icmpv4_service`，将它绑定到已注册 receiver 和一个已启用
resolver 的显式 peer monitor。旧 echo service 与新服务互斥。服务处理请求
后不再重复交给应用；未被服务消费的消息交给原回调。只需要通用 ICMP view
的应用可以显式调用 `ker_transport_receiver_enable_generic_icmpv4`，不启用
自动响应。未启用任一功能的旧 receiver 继续只接收 ICMP echo。

回复只用于本设备、本地单播地址与已配置 peer。回复使用新 IPv4 头，不
反转入站 MAC，而是进入已有的有界邻居解析与 TX 路径。IPv4 options 的回复
语义、输入分片重组和任意多 peer 路由选择尚未接入。extended echo 的 L=0
远端接口发现也明确不支持；查询不会产生虚构的远端状态。

收到 3/5/11/12 时，服务接受中间路由器作为外层源，要求引用方向为本地到
配置 peer，并将 type/code、gateway、MTU、pointer 和有界引用同步交给
`event`。这不是 socket error queue。没有事件消费者时明确返回不支持。
引用地址匹配也不是已经发送过该流的证据；PMTU 更新还需要独立确认。

`ker_icmpv4_service_emit_error` 借用已分类的本地入站 skb，生成受限的
unreachable、time-exceeded 或 parameter-problem 错误。输入 skb 始终归
调用者所有。发送策略抑制广播、多播、无效源、非首片及 error-on-error；
第一片的 MF 不单独构成抑制理由。未知 ICMP 类型也保守抑制。消息经过有界
引用、单调时钟 token bucket 和邻居/TX 队列。burst/refill 配置明确，回拨时钟
失败；计数中的 submitted 只代表提交到输出路径，不代表 NIC 或对端收包。

UTC 回调提供自 UTC 午夜起的毫秒；服务按一天取模，时间不可得时返回错误。
生命周期操作只能由 owner worker 执行；外部时钟和事件回调不能重入改变
正在使用的服务或 monitor 绑定。disable 不取消已排队的回复，清理前必须
正常 drain 或调用所属队列的取消接口。

## UDP 端口未绑定时的自动错误

`udp-endpoint` 为已启用 ICMPv4 service 的 receiver 增加显式、有界的 UDP
端点表。调用者提供零初始化的表和固定地址的 entry 数组，使用非零、网络
字节序的目的端口注册同步回调。相同端口只允许一个绑定，容量用尽返回
`-ENOSPC`；支持下述显式 connected peer 过滤；不支持 wildcard、reuseport 或 socket API。

启用后，receiver 先完成 IPv4/UDP 长度和 checksum 校验，再检查本设备、
本地单播、20 字节 IPv4 头、非零 TTL 和无分片的支持范围。DF 允许；options、
reserved flag、MF、非首片与不支持的地址范围明确丢弃。IPv4 UDP checksum
为零仍按协议作为 omitted 接受。命中端口后只调用对应端点：应用返回
`NET_RX_DROP` 不会生成端口不可达，无效回调状态遵循 dispatcher 的
`-EPROTO` 契约。

查找失败自动调用已有错误服务生成 type 3/code 3，引用实际收到的 IPv4/UDP
字节。无论错误被抑制、限速或输出失败，都不回退到通用接收回调。已绑定
端点可以接收其他有效单播源；错误输出仍限于 monitor 配置的单个 peer。
输入 skb 由 receiver 释放一次，端点只借用 message，不能保留或释放它。

未启用端点表时，原通用 UDP 回调行为保持不变。bind/unbind/disable 仅允许
owner worker 在接收分派之外执行；表存续期间阻止 ICMP service disable 和
receiver unregister。先解除全部绑定，再关闭表和它的依赖对象。

这是 Ker 端点适配，遵循固定 Linux `net/ipv4/udp.c` 中先校验 checksum、
无 socket 时再发送 port-unreachable 的次序。它继续使用原生 checksum 与
邻居输出，但不宣称已经导入依赖 socket、route、XFRM 和 netfilter 的完整
`udp_rcv`。

### 已连接 UDP 端点与生命周期

`ker_udp_endpoint_bind_ex` 返回带 table 身份、slot 和 generation 的句柄；
旧 bind/unbind 接口继续可用。connect 仅接收有效单播 peer IPv4 地址和非零
网络字节序端口，之后只有完整源地址/端口匹配的报文会交付。disconnect
恢复本地端口匹配。对端不匹配属于没有匹配端点，按已有安全策略尝试 3/3；
应用回调返回 DROP 仍不触发错误。

close 或旧 unbind 使旧句柄失效；复用 slot、disable/re-enable 均不会复用
generation。计数溢出返回 `-EOVERFLOW`，不修改端点。调用者重置整个 table
内存表示新的对象生命周期，此前的句柄不得继续使用。connect/disconnect
还推进连接 incarnation，供后续错误交付拒绝旧连接的延迟通知。

当前迭代按 IPv4 单播 L7 proxy 分为四批：端点连接与生命周期、有界接收和
显式 peer 发送、关联真实发送记录的 ICMP 错误与 PMTU、跨 worker proxy
集成。完整 BSD socket、广播/多播、IPv4 分片重组和 IPv6 不属于本轮范围。
有界 UDP IO 适配使用 caller-owned peer registry 和 channel 接收槽。每个槽
立即复制 payload 与四元组；`ker_udp_channel_recv` 返回 1 表示一个 datagram
（包括空报文），0 表示队列为空。PEEK 保留队首；缓冲区不足时报告原长、
复制长度与 truncated，普通 receive 消费整个 datagram。入队时超出配置的
单包空间会截断并记录原长；槽数或字节预算不足丢包，不生成端口不可达。

`ker_udp_send` 使用已连接 peer，`ker_udp_sendto` 使用显式目的，不改变连接
过滤条件。目的必须有同设备、同地址和 worker 的注册 monitor；未知 peer
明确失败。输出为 DF，超过当前 MTU 返回 `-EMSGSIZE`。payload 只在调用中
借用并复制；返回成功仅代表本地邻居/TX 队列接受，不代表 wire 或对端送达。
注册期间 monitor 以及 endpoint table 被适配层 pin；close 丢弃排队 RX，
但不撤回已进入邻居/TX 的独立报文。已提交 TX 不引用 channel 存储。

后续错误与跨 worker 批次合入前，不宣称 IO 队列已完成完整 proxy 集成。

## 显式声明不可用的 IPv4 协议

服务配置中的 `unavailable_protocols` 是复制到 worker-local service 的
256-bit bitmap。第 `p / 8` 字节的 `1U << (p % 8)` 对应协议号 `p`；
默认全零，不对未知协议自动发送错误。应用必须确认自己不提供该协议，
再显式声明。已有 ICMP、TCP、UDP（1、6、17）不能被声明为不可用，enable
返回 `-EINVAL` 且不改变绑定。启用后的配置保持固定；改变声明需先关闭
服务，再用新配置启用。

receiver 完成 IPv4 长度和 checksum 校验后，仅在没有相应 transport
解析路径时调用协议不可用 hook。自动响应要求本地单播、IHL 20、TTL 非零、
无 reserved/MF/offset（DF 允许），并继续应用已有 ICMP 错误发送的源地址、
MAC、显式 peer、速率、MTU 和资源限制。发送的是 type 3/code 2，引用实际
原始 IP 报文。原始数据报仍然丢弃，receiver 保留
`validation_error = -EPROTONOSUPPORT`；服务的 `last_error` 描述错误输出
是否成功，输出失败不会使报文进入通用回调。

如果 runtime 的全局或本设备链上还有其他匹配的 `ETH_P_IP` handler，
自动错误会被抑制，避免与 raw/custom consumer 冲突。这个检查不能只看 skb
引用计数：fanout 前面的 consumer 释放引用后，最后一个 handler 可能重新
拥有唯一引用。其他设备或非 IPv4 handler 不会阻止本设备的回复。

这里实现的是显式受限的协议可用性声明，不是 Linux 全局 `inet_protos`、
raw socket 或 XFRM 策略。固定 Linux `net/ipv4/ip_input.c` 的
`ip_protocol_deliver_rcu` 在协议与 raw consumer 均缺失时发送 protocol
unreachable；Ker 没有用成功 stub 导入这些依赖。TCP/UDP 校验失败、应用
主动丢包、未知 ICMP type 都不会因此被转成 code 2。

## PMTU 的实际作用

零初始化 `ker_icmpv4_pmtu`，为一个显式 peer 绑定初始 MTU、有效期、单调
时钟和 `confirm`。在服务的 code 4 事件回调中，将 `event.message` 和
`event.quote` 传给 `ker_icmpv4_pmtu_apply`。`confirm` 必须根据真实的出站
记录验证所引用的包或流：返回 1 才允许降低 MTU，0 表示无证据，负值表示
验证失败。仅比较地址或无条件返回 1 不能抵抗伪造 ICMP。

更新要求 DF、本地到 peer 的首片引用、MTU 至少 68 且小于被引用报文长度。
非零通告只允许下降；零通告采用 RFC 1191 plateau。缓存有界为一个 peer，
过期恢复初始值，时钟回拨和期限溢出返回错误。monitor 的输出 admission
实际读取该值，过大的新输出返回 `-EMSGSIZE`，保留调用者 packet 和内容。
它不会替应用做 TCP 重分段、UDP 分片或修改已进入 TX/邻居队列的包。

## 测试驱动的移植边界

`icmp-echo` 包含通用报文、错误引用、扩展格式与不变性回归；
`icmpv4-service` 使用两个独立 pool/context、真实 DPDK ring 和 worker，验证
自动响应、邻居解析、错误交付、限速与失败清理；其中 UDP 端点回归验证
双端独立表的同端口交付、应用 DROP 与端口 miss 的区别、实际入站触发的
错误引用与独立 checksum 校验，以及输出分配失败后的恢复。
`icmpv4-pmtu` 验证证据
确认、下降/过期、输出拒绝及 owner/lifecycle。场景来源记录在
[F-Stack 测试映射](fstack-tests.md) 和
[provenance](../tests/fstack-provenance.json)。新增 ICMP 场景是 Ker 扩展，
不是声称复制了 F-Stack 的 ICMP 测试套件。

仍需后续 IPv4 子系统提供的集成包括：转发 TTL 到期、重组超时、socket 异步错误队列、redirect 路由验证与安装、IPv4
options 处理及重组。当前提供可验证的控制接口，不把这些缺失的触发源算作
已完成。接口位于内部 runtime，尚非安装后的公共 Ker API。

协议依据：[RFC 792](https://www.rfc-editor.org/rfc/rfc792.html)、
[RFC 1122](https://www.rfc-editor.org/rfc/rfc1122.html)、
[RFC 1191](https://www.rfc-editor.org/rfc/rfc1191.html)、
[RFC 4884](https://www.rfc-editor.org/rfc/rfc4884.html)、
[RFC 8335](https://www.rfc-editor.org/rfc/rfc8335.html)。
