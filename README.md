# ker 用户态网络栈

ker 的目标是把 Linux kernel 网络栈移植到用户态，以 DPDK 提供网卡收发和运行基础，向上层应用提供 C API，用于高性能 IP、UDP、TCP 服务以及 HTTP 和 WAF 应用。整体方向类似 F-Stack 的 FreeBSD 加 DPDK，但协议实现来自 Linux。

目前是项目初始化阶段：已有依赖 submodule、可编译和安装的 `libker`、能力查询 API 与架构方案。**Linux 网络栈尚未参与编译，DPDK 收发和 socket API 尚未实现，当前不能提供网络服务。** `ker_capabilities()` 返回零，避免把依赖源码存在误报为协议栈可用。

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

需要 C11 编译器和 CMake 3.20 或更新版本。基础库不要求安装 DPDK，也不要求 root、网卡或 hugepage。

```sh
cmake -S . -B build
cmake --build build
./build/ker-info
cmake --install build --prefix "$PWD/build/install"
```

默认生成静态库；`-DBUILD_SHARED_LIBS=ON` 生成动态库。已安装的库可通过 `find_package(ker CONFIG REQUIRED)` 和 `target_link_libraries(app PRIVATE ker::ker)` 使用。公共头文件为 `<ker/ker.h>`，目前仅提供版本与实际能力查询。

## 工程布局

| 路径 | 职责 |
| --- | --- |
| `include/ker` | 上层应用使用的公共 API，不暴露 Linux 或 DPDK 内部类型 |
| `src` | ker 库实现，后续增加 runtime、Linux 兼容层和 DPDK 适配层 |
| `examples` | 公共 API 示例 |
| `cmake` | 安装后供应用查找的 CMake 配置 |
| `third_party/linux` | Linux fork，以 submodule 管理 |
| `third_party/dpdk` | DPDK fork，以 submodule 管理 |
| `docs/architecture.md` | 移植边界、运行模型与分阶段验收标准 |

下一阶段是分析固定 Linux 提交的网络栈依赖，确定最小配置和用户态编译入口，再建立单 worker 的运行环境。详见[架构与移植路线](docs/architecture.md)。
