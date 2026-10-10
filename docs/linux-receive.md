# 单 worker 协议匹配与投递

本阶段逐字编译固定 Linux `net/core/dev.c` 的 `deliver_skb()` 和
`deliver_ptype_list_skb()`，以及原始 `skb_orphan_frags_rx()`、header helpers、
完整 `packet_type` 定义。输入文件 SHA256、选定代码块来源、偏移、行号与版权
均保留。薄包装仅让原始 static matching helper 能被私有 runtime 调用。

## 注册与执行范围

`ker_receive_runtime` 提供单 worker 的协议注册域，使用原始 PTYPE_HASH_SIZE/
MASK。通配处理器存放在 runtime 的哈希桶，设备专属处理器存放在真实
net_device 的 ptype_specific 列表。注册遵守 Linux 的头插顺序，同一列表
最后注册的处理器最先匹配。原始 helper 先遍历通配桶，再遍历设备列表，并
按完整网络字节序 type 匹配，哈希碰撞不会投递到错误协议。

runtime 和 handler 使用调用方的稳定零初始化存储，注册最多 256 个处理器，
无临时报文拷贝、额外分发数组或隐式 heap 分配。每个设备的专属列表只能属于
一个 runtime。runtime pin 其 skb context，专属注册 pin 设备；dispatch 也
临时 pin 设备，因此最后一个回调释放最后一个 skb 后仍不能提前清理设备。
注册、注销、清理在分发回调内被拒绝，避免遍历时修改列表或释放元数据。

原始 helper 中的 RCU list traversal 使用真实 intrusive links 的单 worker
遍历适配，配置并未提供 Linux RCU、跨核注册可见性或 synchronize_net。
enable/disable NAPI、协议注册和 dispatch 均为私有适配接口，不宣称已移植
完整 dev_add_pack/netif_receive_skb/__netif_receive_skb_core。

只接受已经由 Ethernet 分类的线性 skb、唯一 descriptor、同一 context 和
真实输入设备。分发前检查 geometry、L2 header、共享 descriptor、frags/zcopy、
VLAN、pfmemalloc、rx_handler 和 XDP 状态。校验错误保留输入指针与 result。
LLC/IPX、VLAN EtherType、ETH_P_ALL taps、netns、RPS、BPF、TC、netfilter ingress
和非线性用户缓冲尚未适配，明确拒绝。输入带未知的普通 Ethernet II type
仍可进入分发；无匹配处理器时消费并释放输入，返回 NET_RX_DROP。

## 引用与回调契约

保留原始 Linux 的 pt_prev 规则：遇到下一个匹配时，deliver_skb 为前一个
处理器增加 skb->users 引用；最后一个匹配由适配层直接调用，接管输入引用。
每个回调拥有一个引用，必须在所有返回路径释放或保留它。回调返回
NET_RX_SUCCESS/NET_RX_DROP 不代替释放；drop 也必须消费该引用。

多个处理器可能共享同一个 skb descriptor。前面的处理器不能原地修改共享
header/data，也不能改变 type、dev 或注册字段以影响后续遍历。需要修改时先
clone，再 COW，保持其他处理器的数据视图。保留引用的处理器可在回调结束后
继续使用 skb；设备由 context 中存活 skb（包括 clone）的原有保守规则保护。
packet_type 和回调内的设备参数为借用指针，不授权在注销后继续引用 handler。

输入消费后 `*skb` 一定为 NULL，result 报告处理器调用次数和最后一个匹配
处理器的状态，与 Linux 的最终投递规则一致。中间处理器报告 drop 不停止
其他匹配。非法状态返回值会记录 -EPROTO，但仍投递剩余匹配且输入已经消费；
调用方必须根据指针和 result 判断所有权，不能仅凭负 errno 重试输入。
回调未消费引用、破坏 skb 字段或直接修改私有 native 状态属于契约违规。

skb_copy_ubufs 的未支持分支返回错误，不能伪装复制成功。有效输入在分发前
已排除 frags/zcopy，因此原始 orphan helper 走真实的无需复制路径。分发重置
network header、必要时初始化 transport header，设置 mac_len 与 skb_iif。
这些不是 IPv4 内容或 checksum 校验；PACKET_OTHERHOST 的后续拒绝仍需由真正
的协议入口实现。

## 验证与后续

真实 EAL 验证通配与设备匹配顺序、哈希碰撞、另一个设备的专属匹配、未知协议
丢弃、retained skb 引用、clone 后 COW、设备/context pin、容量上限与注销、
错误 worker、回调中修改注册/重入、共享 descriptor 和未支持 metadata 的
不变所有权、非法回调返回值的已消费状态。worker → NAPI → Ethernet → 原始
匹配/投递 → 测试消费者的链路也验证了按预算处理。

测试消费者处理 IP/ARP EtherType 的示例 payload，不是真实 ip_rcv/arp_rcv。
公开能力仍仅为 checksum。下一步接入原始 ARP/IPv4 入口与设备地址、邻居及
发送路径，使软件测试链路能够验证 ARP 应答和 ICMP ping。
