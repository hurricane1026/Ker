# Linux skb 线性子集与 DPDK 接入

本阶段将 Linux 原始 `sk_buff`、`skb_shared_info` 结构及选定的原始函数接入 DPDK 内存后端，完成单 worker 下的线性包生命周期验证。完整 `skbuff.c`、非线性 skb、路由、socket、net_device、NAPI 和 IP/UDP/TCP 协议处理仍未接入。接口保存在 `src/runtime/skb.h`，不安装为公共 API。

## 原始源码导入范围

`tools/import-linux-skb.py` 从固定 Linux submodule 按明确的定义列表逐字导入源码。结构体保留完整字段、条件编译块和原始匿名结构分组，配置限定为 64 位小端、17 个 fragment slot，并禁用本批代码涉及的可选子系统。没有手写简化版 sk_buff 布局。

`src/compat/linux-skb-manifest.json` 保存九个输入文件的 SHA256。任何输入变化都会阻止配置，需要先检查所选定义和适配边界，再更新清单。构建目录 `linux-skb/provenance.json` 记录每个导入块的源文件、行号、字符范围和 SHA256；生成的代码使用原始源码行号，便于检查编译错误。

| 原始源码 | 导入内容 |
| --- | --- |
| `include/linux/skbuff.h` | skb/shared info/fragment/timestamp 类型，以及 users、dataref、headerless、几何和线性操作 helper |
| `net/core/skbuff.c` | `__finalize_skb_around`、`__copy_skb_header`、`__skb_clone`、`skb_headers_offset_update`、put/push/pull/trim |
| `include/linux/types.h` 与 `llist.h` | 原始 list 与 KCOV handle 类型 |
| `include/net/netmem.h` | 原始 netmem_ref 类型，fragment 操作仍不支持 |
| `kconfig.h` 与 `stddef.h` | 原始配置判断和结构分组宏 |
| `kcov.h` | 禁用 KCOV 时的原始 handle helper |

这是配置固定的源码子集，不是整棵 skb 头文件或整个 skbuff.c 的构建。生成器保留原始函数内容，分配、回收与 DPDK 转换由桥接代码实现。非空 dst 状态被明确拒绝，配置 guard 阻止启用尚未适配的 conntrack、extensions、trace 等设施。

## 描述符与 backing

DPDK mempool 分配一个私有 envelope，其中包含原始 skb 和外部 backend 信息。backend 不增加原始结构字段，也不占用 `skb->cb`。context 和池对象需要保持地址稳定，所有 skb 操作只能由所属 EAL worker 执行。

backing 使用一份唯一 direct mbuf 的 data room。尾部预留按 cache line 对齐的 skb_shared_info，Linux 的 end 指向它的起始位置；put 操作只能使用 end 之前的容量。转换前检查 mbuf 的对齐、segment、引用和包几何，防止 shared info 覆盖活跃数据。

| 动作 | 描述符引用 | Linux backing 引用 | DPDK 引用 |
| --- | --- | --- | --- |
| 分配 skb | users 为 1 | dataref 为 1 | 一份 mbuf 引用 |
| get 同一个 skb | 增加同一描述符的 users | 保持不变 | 保持不变 |
| clone skb | 新描述符 users 为 1 | 原始 clone 增加 dataref | 仍由这一份 mbuf 引用承载 |
| 释放描述符最后一个 users | 释放该描述符 | 用原始 data_unref 判断是否最后一份 backing 引用 | 最后一份 backing 引用释放时归还原池 |

mbuf 被 skb 接管后，其包内容和几何由 Linux skb 管理，不能再通过外部 native mbuf 操作修改它。Linux clone 使用原始 clone 算法，共享原始 shared info，不创建 DPDK indirect mbuf，也不将 Linux dataref 替换成 DPDK refcount。

## Headerless 引用与 COW

原始 `__skb_header_release`、`skb_header_cloned` 和 `skb_data_unref` 保留 dataref 的高低 16 位语义。TCP 形式的 payload-only owner 使用高位 bias，clone 保留 hdr_len 并产生独立描述符；释放或 COW 必须同时处理对应的 bias。

`ker_skb_make_writable` 要求唯一描述符，从配置的 packet pool 分配新 backing，复制已有 headroom、活跃报文和 shared info 元数据，再将新 dataref 初始化为一。成功后更新原始 header offsets，最后释放旧 backing 引用。分配失败或新池容量不足时，原 skb、引用计数和所有权保持不变。

这个接口保证请求的最小 headroom/tailroom。增加 headroom 可以消耗现有空闲 tailroom，活跃报文和已 pull 的头部会保留。未请求的空闲 tailroom 内容不属于复制保证。

put/push 要求唯一描述符与唯一数据 backing；共享数据需要先 COW。pull/trim 只修改唯一描述符的几何，可以继续共享 backing。原始 panic 条件之前有受控的边界检查，失败不修改输出指针。

## 接收与导出

`ker_skb_from_mbuf` 仅在成功后接管输入 mbuf。它要求唯一 direct 单 segment，在足够的尾部空间内初始化 shared info，并用原始 reserve/put 设置 skb 几何。失败时输入 mbuf 仍由调用者负责。

`ker_skb_to_mbuf` 从配置池分配另一份 mbuf，复制活跃 skb 字节。输出由调用者持有，原 skb 与 backing 不转移。当前不声明 TX offload；partial checksum 或 GSO 发送状态返回 ENOTSUP，不能把尚未完成的处理静默交给网卡。

page fragments、frag_list、external/indirect mbuf 的接管、fclone、page pool recycling、路由 dst 引用等状态不支持。native packet pool 的多 segment 功能不代表这个 skb bridge 已支持非线性 skb。

## 验证与下一阶段

真实 EAL 下验证了描述符与数据引用的独立生命周期、原始 headerless bias、两种 COW、头部偏移、cb 与元数据复制、接收所有权、复制导出、池耗尽、故障注入、跨池 backing、最终回收及错误 worker 拒绝。源码导入测试逐块比较原始内容，检查输出稳定性、源码变化拒绝和编译器对不支持配置的拒绝。

GCC 静态 Debug、动态 Release 和 Clang ASan/UBSan 检查通过；DPDK 自身仍未启用 sanitizer。目前运行验证的平台是 x86_64 Linux，没有真实网卡、IP/UDP/TCP 或多 worker 互通测试。

下一阶段需要建立 net_device 和 NAPI 运行入口、接口配置与协议注册，并扩展所需 skb helper，逐步引入原始 Ethernet、ARP 和 IPv4 源码。公开能力位继续只声明 checksum，直到实际协议和网卡路径通过验收。
