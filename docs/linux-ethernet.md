# 原始 Linux Ethernet 接收分类

本阶段直接编译固定 Linux 源码中的 `eth_type_trans` 和
`eth_header_parse_protocol`，保留完整原始 `struct net_device`、其嵌入的
`struct device` 及必要布局类型。生成代码来自显式选择的逐字片段，输入文件
由 SHA256 manifest 固定，每段记录源文件、行号、偏移与摘要，并保留来源版权。
没有使用只包含 MAC/ifindex 的替代结构，也没有直接编译完整 eth.c/dev.c。

## 有效范围

私有 `ker_eth_device` 用 DPDK heap 分配完整原始 net_device，初始化 MAC、广播
地址、接口索引及用户态锁。设备始终为 NETREG_UNINITIALIZED；它是供二层分类
使用的未注册设备视图，不宣称 register_netdevice、driver model、sysfs、PM、
路由、邻居或 NAPI 已实现。嵌入的这些服务状态保持不活跃，不调用其内核操作。

结构定义在受控配置下原样编译；mutex/spinlock/refcount 等基础类型沿用 ker
兼容层。内核 dev_t 通过私有类型命名隔离，保留原始 32-bit typedef，避免
误用 libc 的 dev_t。仅支持已有的 64 位小端目标；选定片段的可选 CONFIG 与
MODULE 激活会阻止编译。DSA、netns、BPF 等路径没有通过空成功函数模拟。

原始 Ethernet helper 用 Linux 的 __BIG_ENDIAN 条件判断。libc 的同名常量在
小端机器上也可能定义，因此生成头局部保存/清除并恢复它，用 DPDK byteorder
适配 htons；原始片段不改写。禁用 efficient-unaligned helper 分支，接收地址
要求 u16 对齐。不支持的奇地址在转移所有权之前返回 EINVAL。

## 接收与所有权

`ker_eth_receive` 的路径是 native mbuf → 原始 Linux skb → 原始 eth_type_trans。
成功后，skb 保存真实设备指针、原始 packet type 和 protocol，MAC 头保留在
headroom，data 指向二层负载；适配层设置 mac_len 并用原始 helper 设置
network_header。分类包括本机、广播、多播、OTHERHOST、Ethernet II、802.2
和 Linux 的旧 IPX 判定。

这一步只分类，不调用 ARP/IPv4 处理器，不按协议类型假装已经处理报文。
未知 EtherType 也能返回分类结果，由后续接收分发层决定如何处理。
不验证 IPv4 内容、CRC、MTU 或完整 802.3 长度字段；不能将分类成功视为
报文内容有效或可以进入某个尚未适配的协议路径。

短于 ETH_HLEN 的帧在接管前返回 EMSGSIZE；alignment、共享/非线性/external
backing、未映射 RX offload 或描述符耗尽等失败路径保持 mbuf 与输出所有权。
原始 header-pointer helper 的 fallback 使用有边界检查的线性 copy 适配；
非线性 copy 明确失败，不伪装为成功。短 LLC payload 仍遵守原函数的 fallback。

设备与 skb context 属于同一 worker，地址必须稳定。当前采用保守的设备寿命
规则：context 中任何 skb（包括 clone）仍存活时 cleanup 返回 EBUSY。这让
原包释放后的 clone 仍能安全访问 skb->dev。尚未引入按设备的引用 pin 或
在线注销；同一 context 的其他无关 skb 也会阻止设备清理。

关闭时先回收所有 skb，再 cleanup 设备、context 和 packet pool，最后关闭
memory context。设备 cleanup 不释放 context 或包池；借用的 context 结构
必须保持有效直到设备 cleanup 完成。

## 验证与下一步

真实 EAL 验证各 packet type/协议分类、MAC 与 network header 几何、原包和
clone 的设备寿命、短帧/奇地址/stripped metadata/池耗尽的不变所有权、错误
worker 和最终回收。worker RX 回调测试按预算接管 IP/ARP EtherType 帧、执行
原始二层分类并交给测试消费者释放；这不是 PMD 收发或真实 ARP/IPv4 应答。

导入测试逐字验证片段、稳定输出及版权来源，使用真实编译器拒绝未适配配置，
验证 host endian 常量恢复，并确认 Linux 输入变更会在生成文件之前被拒绝。

下一步适配原始 NAPI 调度与接收分发，然后接入 ARP、IPv4、ICMP 和邻居/地址
配置，以软件测试链路验证 ARP 应答与 ping。公共 capability 仍仅声明 checksum。
