# 原始 ARP 与 Ethernet 报文构造

直接编译固定 Linux `net/ipv4/arp.c` 中的 `arp_create()` 和
`net/ethernet/eth.c` 中的 `eth_header()`，完整导入原始 header_ops、arphdr、
ARP/header helpers 和 LL_RESERVED_SPACE 常量。输入文件由 SHA256 固定，
选定代码块逐字保留，并记录源文件、行号、偏移、摘要和版权。

## 私有构造接口

ker_arp_device_setup 为现有未注册 Ethernet 设备视图安装真实原始 eth_header
和 eth_header_parse_protocol 操作。它不注册设备、配置 IP 地址、创建邻居表
或连接驱动；也不会覆盖调用方已安装的其他 header_ops。操作表是静态只读
存储，不需要单独销毁。构造接口只支持 Ethernet，MAC 长度 6、头长度 14，
且 needed_headroom/tailroom 为零；loopback/noarp 或其他设备类型明确拒绝。

ker_arp_create 支持 ARPOP_REQUEST 与 ARPOP_REPLY，地址为网络字节序。请求
允许 NULL destination/source/target MAC，遵循原函数的广播、设备源 MAC 和
全零目标 MAC 默认规则；应答要求显式提供 destination 和 target。参数描述
报文字段，不验证地址归属、IP 路由或是否应答某个收到的请求。

alloc_skb 适配只在原始构造函数的同步调用范围内启用，以线程局部的实际
skb context 分配 descriptor 和原生 DPDK mbuf。GFP_ATOMIC 走已有固定资源
后端，不回退到 libc 或通用 heap；所需 headroom/payload 由原函数计算并
保留/填充。原始 dev_hard_header 调用真实 eth_header，后者通过原始 skb_push
填 Ethernet 头。header_ops 固定为上述表，不引入可重入应用回调；错误 worker、
未初始化后端、未安装 header_ops 和非法参数在构造前拒绝。

失败保持输出不变；分配错误恢复调用范围并回收已取得资源。成功返回包含
Ethernet 头的一个 caller-owned skb，protocol=ARP，network_header 指向
arphdr，MAC geometry 由包装初始化。原函数完整填充 42 字节的 Ethernet/ARP
请求或应答；不添加 Ethernet 最小帧 padding、CRC 或 PMD offload 声明。

## DPDK 导出与 TX 范围

已有 ker_skb_to_mbuf 显式复制报文到新的 caller-owned mbuf，成功不消费原 skb。
导出失败保持 skb 和输出所有权，调用方可归还资源后重试；成功后由调用方释放
skb，并交接 mbuf。当前没有零拷贝 TX 引用转移、TX burst 部分接收/重试或
completion 管理，不能将复制导出成功视为网卡已经发送。

worker TX 回调测试实际完成构造结果导出、skb 释放和 mbuf 所有权交接，再将
报文送入另一个真实设备视图的 Ethernet 分类与协议投递，以测试消费者检查
并释放。这个软件回环只验证构造字节与现有链路，未调用真实 arp_rcv/arp_process。

## 配置、验证与后续

原始 IFF enum 在私有命名空间下编译，局部保存并恢复 glibc net/if.h 的宏，
避免宿主 flags 替换或枚举冲突。htons 在生成源中绑定 DPDK byteorder。
AX25、NETROM、FDDI、FIREWIRE_NET 等未适配 CONFIG 与 MODULE 会阻止构建。

真实 EAL 测试逐字比较请求与应答，包括 Ethernet 地址、type、ARP hardware/
protocol/length/opcode 及四组地址；验证 clone 设备寿命、导出内容与无 offload、
分配失败、mbuf 池耗尽、导出失败后重试、错误 worker、非法参数、未适配 headroom，
以及 worker TX 与软件回环。导入测试验证原始代码/来源、稳定输出、输入变更
拒绝、CONFIG/MODULE 失败和 glibc flags 共存。

当前没有 arp_xmit/NF_HOOK、arp_rcv、arp_process、自动 ARP 应答、邻居更新或
真正 IP 收发。下一步接入地址/邻居和发送调度，再移植真实 ARP 接收与 IPv4/ICMP
入口。公共能力仍仅声明 checksum，协议服务与网卡性能仍需后续验证。
