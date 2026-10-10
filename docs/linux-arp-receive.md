# 原始 ARP 接收门控与私有报文回调

这一阶段逐字导入 Linux arp_rcv、skb_share_check、pskb_may_pull_reason、
默认配置的 skb_might_realloc、GFP blocking predicate，以及完整 drop reason
枚举和 neighbour_cb。导入源由 SHA256 固定，保留版权与逐片段来源信息。
CONFIG_NETFILTER、CONFIG_FAIL_SKB_REALLOC、CONFIG_DEBUG_NET 及 MODULE
形式均拒绝；其他依赖切片仍受既有配置边界约束。

## 接收与所有权

ker_arp_receiver_register 在既有 receive runtime 上注册设备专属 ETH_P_ARP
handler，并额外持有 IPv4 address/in_device 引用。地址、设备和 receiver wrapper
必须保持稳定地址；移除 handler 后才释放地址引用。注册失败不留下 pin。
所有操作属于同一 worker；dispatch 期间不能注销或清理相关对象。

原始 arp_rcv 处理 IFF_NOARP、PACKET_OTHERHOST 和 PACKET_LOOPBACK 忽略分支，
检查 ARP 长度和硬件/协议地址长度，并清理 neighbour_cb。接收分支始终消费
一个 handler-owned skb 引用。其他 handler 保留同一 descriptor 时，原始
skb_share_check 经实际 DPDK descriptor 池克隆，释放当前旧引用后处理新描述符；
克隆失败也释放当前引用，不损坏其他 handler 的持有引用和 scratch。
只共享线性数据 backing；ARP 接收不写报文数据。非线性片段未支持，正常边界
不能到达 pull-tail；意外到达会终止而不是伪造成功。

## 私有解码回调边界

本阶段没有导入完整 arp_process。原始 arp_rcv 的 NF_HOOK 调用位置由明确的
私有同步 handoff 适配到 ker_arp_rx_process，未实现 netfilter hooks、namespace、
FIB、proxy、动态 NUD、ARP 学习或自动应答。netfilter 配置被拒绝；不能把此
适配称为内核 NF_HOOK/arp_process 的等价实现。

私有解码支持 Ethernet 上的 IPv4 request/reply，接受 Ethernet/IEEE802 ARP
hardware type。目标和非零源 IP 必须是本 profile 的非零、非 loopback、非
multicast/class-E IPv4 地址；源 MAC 必须非零单播。源 IP 为零仅接受 request，
作为 DAD 消息传递。比完整内核策略更严格的地址拒绝在此明确限定。
不将任何接收结果自动写入永久邻居表，亦不声明发送者真实性。

回调收到复制后的 sender/target IP、MAC、operation 和 target_local；local
判定仅比较配置地址，不替代路由/ARP ignore/filter 策略。有效非本地目标也
传递给回调，padding 被忽略。回调只借用消息，没有 skb 或数据指针所有权。
回调返回 SUCCESS 或 DROP；非法返回由既有 dispatcher 报 EPROTO，但输入已
消费，不能依据负返回再次释放输入。

回调可使用已有原始 arp_create 构造应答并放入自身有界发送队列；构造失败和
背压由调用方处理。本阶段测试完成 request→门控→复制消息→原始 reply 构造，
不包含生产自动应答、PMD 或重试发送。同步 handoff 使用线程作用域；嵌套 ARP
接收拒绝并消费自己的引用，不替换正在处理的 scope。

## 验证与后续

真实 EAL 测试覆盖全部 0..27 字节短包、地址长度/类型/operation/IP/MAC 错误、
padding、DAD、非本地目标、request/reply、忽略分支、错误 worker、注册失败
回滚、地址/device pin、回调状态和 dispatch 期间注销拒绝，及共享 descriptor
克隆成功、注入失败和真实固定池耗尽后的精确引用与资源回收。
导入测试覆盖原始代码、稳定输出、配置拒绝和未审查源修改。

下一步为动态邻居解析、probe/重试定时器、有界待解析队列与 TX 完成路径建立
真实状态机，再移植依赖它们的原始 arp_process 分支。公共 capability 仍为
checksum，本阶段不提供完整 ARP/IP 网络服务。
