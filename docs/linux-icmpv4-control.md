# ICMPv4 控制服务

Ker 保留无状态 ICMPv4 报文 view/create 适配器和通用控制服务。它使用
原生 Linux checksum helpers、worker receiver 和邻居/TX adapters；不会替代
依赖 socket、FIB、netns、IPv4 重组的 Linux ICMP 路径。IPv6/ICMPv6 不在范围内。

## 报文适配

ICMPv4 view 校验 IPv4/ICMP 长度与 checksum，并借用只在 callback 期间有效的
数据。构造器为调用者创建报文 skb；调用者负责其生命周期。错误报文构造有
明确的引用长度边界，但构造器本身不决定发送策略。

通用服务可处理受支持的 echo/timestamp/extended-echo 请求，并把配置的控制
错误同步交给事件 callback。未启用服务时，receiver 的默认行为保持不变。
错误生成受地址、分片、error-on-error、token bucket、邻居和 TX 队列约束；
提交到本地输出队列不代表 NIC 或对端已收到。

`unavailable_protocols` 是显式配置的未知 IPv4 protocol bitmap。默认不自动
拒绝未知协议；调用方声明某协议不可用后，服务仅对有效的本地单播报文按
ICMP 规则尝试生成错误。已知的 ICMP/TCP/UDP protocol 不能声明为 unavailable。

## 未实现的传输层策略

Ker 不包含 TCP/UDP 连接状态、socket 错误队列、ICMP 错误关联或 PMTU cache/
policy。未知或延迟 ICMP 错误不会被转换成 TCP/UDP 连接事件，也不会改变
后续 packet constructor 的 MTU。TCP/UDP 能力仅限无状态 view、checksum 和
报文构造/ownership adapters；完整行为需由导入的 Linux 实现提供。
