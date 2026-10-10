# ker 用户态网络栈

ker 的目标是把 Linux kernel 网络栈移植到用户态，以 DPDK 提供网卡收发和运行基础，向上层应用提供 C API，用于高性能 IP、UDP、TCP 服务以及 HTTP 和 WAF 应用。整体方向类似 F-Stack 的 FreeBSD 加 DPDK，但协议实现来自 Linux。

目前已开始基础代码移植：`libker` 直接编译 Linux 原始的 `lib/checksum.c`、`lib/rbtree.c` 和 `lib/timerqueue.c`，提供校验和 API 以及内部单线程定时器运行环境。**skb、IP/UDP/TCP 协议层、DPDK 收发和 socket API 尚未实现，当前不能提供网络服务。** `ker_capabilities()` 返回 `KER_CAP_CHECKSUM`（`0x20`），协议栈和网卡能力仍关闭。

## 获取依赖

```sh
git submodule update --init --recursive --depth 1
```

依赖位于 `third_party/linux` 和 `third_party/dpdk`，来自 `hurricane1026` 的 GitHub fork。主仓库通过 gitlink 固定具体提交；日常构建不要使用 `git submodule update --remote`。初始提交取自 fork 的默认分支，尚未验证为可移植的版本组合。

| 依赖 | 源码声明版本 | 固定提交 |
| --- | --- | --- |
| Linux | 7.3.0 rc6 | `3857c2fe5449541e24afc5efdb0f81a8a8f9a3a0` |
| DPDK | 26.11.0 rc0 | `d129414711aa7c4954f997acf4c54338574a7d92` |

版本字段来自各自源码；这两个提交均属于开发版本。进入协议栈移植阶段前，应评估是否改用 fork 内的稳定版本作为长期基线。

## 编译基础库

当前支持 Linux 主机上的 GCC 或 Clang，需要 GNU C 扩展和 CMake 3.20 或更新版本。构建需要初始化 Linux submodule；无需内核配置或生成内核头文件，不要求安装 DPDK、root、网卡或 hugepage。

```sh
cmake -S . -B build
cmake --build build
./build/ker-info
./build/ker-checksum
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/build/install"
```

默认生成静态库；`-DBUILD_SHARED_LIBS=ON` 生成动态库。已安装的库可通过 `find_package(ker CONFIG REQUIRED)` 和 `target_link_libraries(app PRIVATE ker::ker)` 使用。`<ker/ker.h>` 提供版本和能力查询，`<ker/checksum.h>` 提供 Internet checksum 与 IPv4 transport pseudo-header checksum。结果为网络字节序，可以用 `memcpy` 写入包头，无需 `htons`。测试默认开启，可用 `-DBUILD_TESTING=OFF` 关闭。

## 工程布局

| 路径 | 职责 |
| --- | --- |
| `include/ker` | 上层应用使用的公共 API，不暴露 Linux 或 DPDK 内部类型 |
| `src/compat` | 私有 Linux 兼容头文件和符号隔离声明 |
| `src/runtime` | 基于 Linux timerqueue 的单线程定时器运行环境 |
| `tests` | 校验和、包字节序、定时器行为与红黑树不变量测试 |
| `examples` | 公共 API 示例 |
| `cmake` | 安装后供应用查找的 CMake 配置 |
| `third_party/linux` | Linux fork，以 submodule 管理 |
| `third_party/dpdk` | DPDK fork，以 submodule 管理 |
| `docs/architecture.md` | 移植边界、运行模型与分阶段验收标准 |

当前移植边界及验证方法见[首批 Linux 基础代码移植](docs/linux-port.md)。下一阶段是建立 skb 所需的内存和引用计数语义，再推进 net_device 与 IPv4 协议代码。整体路线见[架构与移植路线](docs/architecture.md)。
