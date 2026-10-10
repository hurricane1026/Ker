# 原始 IPv4 地址布局与静态配置

本阶段完整导入 Linux 的 ipv4_devconf、in_device、in_ifaddr、callback_head
以及原始 inet_make_mask()/inet_ifa_match()。逐字片段的文件哈希、来源偏移、
行号、摘要和版权均保留。原始 htonl 仅在生成头局部绑定 DPDK byteorder，
恢复宿主宏；配置不支持 multicast 或 sysctl 服务，CONFIG/MODULE 明确拒绝。

## 有效状态

每个私有 Ethernet 设备可安装一个永久静态 IPv4 地址，以原始 net_device.ip_ptr
关联真实 in_device/ifa_list/in_ifaddr。两个完整对象共用一次 GFP_KERNEL 的
DPDK control allocation，没有 libc 回退。初始化 local/address、prefix、mask、
broadcast、scope、永久 flags/lifetime、label、设备反向指针与 refcount。
cnf、multicast timers、arp_parms、sysctl 和 RCU callback 等未移植服务保持不活跃。
仅填充这些地址字段不意味着 inetdev_init 或完整 IP 栈已经可用。

输入为网络字节序，prefix 为 0..32；Ethernet 边界拒绝零地址、127/8、multicast、
class-E 和 limited broadcast。未实现完整 Linux 地址验证器、别名、点对点配置
或 secondary address。literal broadcast 字段为 local | ~mask；/31 与 /32
不会据此宣称具有广播路由，仍需将来 FIB/地址分类处理其协议语义。

contains 使用逐字原始 prefix predicate；/0 匹配所有候选值，/31 与 /32 严格
按位匹配。is_local 仅比较 ifa_local。两个查询不是 inet_addr_type、FIB lookup、
源地址选择、网关判断或包接收判定，不能用 prefix 匹配代替本机地址匹配。

## 所有权和清理

wrapper 和设备存储稳定，所有操作限于已初始化的同一 worker。地址 pin 设备
及 skb context，防止它们先被清理。setup/cleanup 需要该 context 无活 skb，
设备没有绑定的 NAPI 或协议 handler/正在分发的 pin；状态变化是离线控制操作，
不提供在线重配置或跨核 reader grace period。额外原始 in_device refcount
也会阻止 cleanup。失败不改变 wrapper 或 ip_ptr，分配失败回滚容量占用，峰值统计沿用分配器语义。

ip_ptr 的 publication/读取使用已有真实原子指针操作；RCU callback 布局保留
不意味着有 RCU 服务。清理在 worker quiescence 下解绑指针并释放实际 DPDK
allocation；先销毁 handler/NAPI 和 skb，再清理地址、设备与 context。

## 验证与下一步

真实 EAL 测试验证 /0、/1、/8、/24、/31、/32 的 mask 与 prefix/local 查询、
完整字段/label/lifetime、非法地址/prefix、分配失败回滚、重复设备配置、
错误 worker、设备/context pin、原始 refcount 额外引用、skb/clone 和 NAPI/
协议 handler 的清理阻塞。配置地址也实际作为原始 arp_create 的源 IP，按
字节验证构造结果。导入测试验证原始片段、稳定输出、宿主 byteorder 共存、
未适配配置拒绝和输入变更失败。

没有路由安装、netlink、sysctl、IGMP、ARP 邻居参数、自动 ARP 应答或 IPv4
报文处理。下一步补齐邻居与发送调度等真实 ARP 接收依赖，再接 IPv4/ICMP。
公共 capability 仍仅为 checksum，不能据静态配置宣称已提供网络服务。
