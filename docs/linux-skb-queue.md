# 原始 skb FIFO 与有界待发送队列

这一阶段为后续动态邻居等待/重试和发送调度建立实际有界资源容器，没有启动
动态 NUD 或 ARP 学习。逐字导入原始 __skb_insert、__skb_queue_before、
__skb_queue_tail、skb_peek、__skb_unlink、__skb_dequeue，复用已导入的完整
sk_buff_head 和初始化代码。输入仍由 neighbor manifest 固定，新增片段也有
原始版权、行号、偏移和摘要；没有替换为自行实现的列表。

## 限额与所有权

ker_skb_queue 是调用方持有、稳定地址、零初始化的 worker 私有 FIFO。初始化
不分配堆内存，也没有新的 DPDK pool，队列容器本身 pin skb context。队列
要求非零 packet_limit 和 byte_limit，push/pop 不分配、不克隆、不淘汰旧包，
不回退到 heap。原始无锁 __skb_* 操作由同一 worker 生命周期串行化；嵌入
spinlock 真实初始化，但不宣称实现跨核 MPMC 队列。

成功 push 移交一个独占 descriptor 引用并将输入指针清空；失败保持输入和
队列不变。共享同一 descriptor、已经链接到其他列表、跨 context/worker 的
包被拒绝。不同 descriptor 可以共享 backing，遵守既有 Linux dataref/COW
语义。队列不能接管一个 descriptor 的多个引用来支持同时修改。

包数限额与 bytes 限额同时生效。bytes 是入队时冻结的 Linux truesize 总和，
不是 len/payload 字节；空或很短的包也会占用实际 retained capacity 上限。
共享 backing 的多个 descriptor 会重复保守计数，不宣称精确物理字节计量。
这不是第二次 DPDK worker capacity budget 扣账：原分配/clone 已在既有内存
域预算和固定池中计费，队列只增加保留策略限额。出队按冻结值归还队列计数。

队列归属与 frozen charge 放在私有 skb envelope，既不更改原始 skb 布局，也
不占用 cb 或报文内容。入队后，ker_skb_validate/get/free/clone/COW/export/
put/push/pull/trim 均返回 EBUSY；旧裸指针不能越过 ownership transfer 继续
操作。直接调用原始 native helpers 或修改字段绕过此保护违反接口契约。

pop 返回一个已解除 native links 的调用方引用；空队列和错误不更改输出。
出队后的包可以导出、修改或释放。队列 bytes 此时下降，但调用方仍持有的
backing/descriptor 会继续占用真实 DPDK 资源和原始 worker budget。

## 回收与 TX 背压

purge 最多释放 budget 个描述符，budget 0 不做工作。每次先原始 unlink，
清除 private owner 和计数，再调用既有 skb free/destructor。每张队列有独立
purging 状态；destructor 不得重入当前队列，嵌套清理其他队列也不能绕过外层
保护。cleanup 只接受空且未 purging 的队列，释放 context pin；没有静默
丢弃待发送包。context 即使没有 live skb，也不能在有空队列 pin 时销毁。

队列不等价于 NIC TX completion。worker TX callback 出队后持有引用，若
copy-export 因 mbuf 池耗尽失败，应保留该引用后续重试；成功提交后的释放
时机仍由发送适配器定义。本阶段用既有 worker 和真实池验证此生命周期，
没有 ethdev/NIC offload、动态邻居定时器或自动 ARP 应答。

## 验证与后续

真实 EAL 测试覆盖 FIFO 回收再入队、count/truesize 满额保留所有权、空包、
共享 descriptor 拒绝与共享 backing admission、跨 worker/context、重复入队、
全部 queued API 拒绝、cb/数据保留、冻结 debit、context pin、分批 purge 和
嵌套 destructor 重入保护；在固定 descriptor 池满时仍能完成无分配入队。
TX 测试在真实 mbuf 池耗尽后保留已出队引用，并在资源回收后完成下一轮发送。
既有 neighbor-import 验证新增原始 helper 片段、稳定输出和配置拒绝。

下一步把该队列接入真实邻居 entry 的 unresolved 生命周期、probe/retry 与
失败回收，再移植相关原始 __neigh_event_send/arp_process 分支。当前队列
独立于永久邻居表，不将永久条目伪装成动态 NUD。公共 capability 仍为 checksum。
