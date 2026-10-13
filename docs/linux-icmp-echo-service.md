# 有界 ICMP echo 自动回复

`ker_icmp_echo_service_enable` 将一个 echo 服务绑定到已注册的
`ker_transport_receiver` 和已启用 resolver 的显式 IPv4 peer monitor。
服务在接收路径完成 IPv4/ICMP 校验后处理 type 8 请求；UDP、TCP 和 type 0
仍由原应用回调接收。禁用服务后，请求也恢复交给该回调。每个 receiver
最多绑定一个服务，不额外注册 ETH_P_IP handler。

服务仅接受本设备 PACKET_HOST、目的地址为配置的本地地址、源地址等于
monitor peer 的请求。IPv4 TTL 必须非零，仅支持无 options 的 20 字节头，
fragment 字段只能为零或 DF。广播、其他 peer、其他本地目标、IPv4 options
和不支持的 fragment profile 明确拒绝；完整 IP/ICMP checksum 检查仍由现有
view adapter 执行。

回复使用配置的本地 IP/MAC，复制请求 identifier、sequence 和 payload，
采用服务配置的 TTL 和新建的零值 IPv4 field profile。构造期间的零目的 MAC
只是内部占位值：实际回复通过原生 `neigh_resolve_output` 重新生成 Ethernet
头，不从入站请求学习 MAC，也不直接反转请求的二层地址。

peer 尚未解析时，原生有界邻居队列保留回复并触发现有 ARP probe callback；
调用方仍负责把 probe 接到 TX，并把 ARP receiver 接到 scoped neighbor
feedback。有效反馈使原生队列 flush 到已有 TX exporter。队列限制、淘汰、
超时和取消沿用 monitor 的现有语义。`replies_submitted` 只表示输出路径接受
了回复，不能作为实际发送或对端收到的计数。

启用期间，adapter reference 阻止 receiver unregister、monitor cleanup 和
resolution disable；它不增加原生 neighbour 引用，避免改变 native output
的引用计数条件。enable/disable 是 owner worker 的离线配置操作，回调执行
期间拒绝改变绑定。禁用服务不释放已进入邻居或 TX 队列的回复，调用方必须
正常 drain 或使用对应队列的取消接口，然后按依赖次序清理。

本功能是 Ker 的受限服务组合，复用原始 Linux checksum/neighbor/ARP 路径，
没有移植完整 `icmp_rcv`/`icmp_echo`，不提供 socket、路由、通用 ICMP 错误、
广播 echo、源路由或 NIC 支持。测试使用同一 EAL thread 上两个逻辑 peer 的
独立 pool/context 和真实 DPDK ring，不宣称跨 CPU 的新覆盖。F-Stack 场景
来源及差异见 [测试映射](fstack-tests.md) 和
[provenance](../tests/fstack-provenance.json)。
