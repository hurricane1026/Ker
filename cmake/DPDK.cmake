find_package(PkgConfig REQUIRED)
set(KER_DPDK_PKGCONFIG_DIR "${PROJECT_SOURCE_DIR}/third_party/dpdk/install/lib64/pkgconfig"
    CACHE PATH "pkg-config directory for the DPDK fork build")
if(NOT EXISTS "${KER_DPDK_PKGCONFIG_DIR}/libdpdk.pc")
    message(FATAL_ERROR "Build the DPDK fork with tools/build-dpdk.sh, or set KER_DPDK_PKGCONFIG_DIR explicitly")
endif()
set(ENV{PKG_CONFIG_PATH} "${KER_DPDK_PKGCONFIG_DIR}:$ENV{PKG_CONFIG_PATH}")
# The host's older DPDK must not silently substitute the selected fork baseline.
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk>=26.11.0)
add_library(ker_dpdk_port OBJECT src/runtime/memory.c src/runtime/buffer.c)
target_link_libraries(ker_dpdk_port PRIVATE ker_port_headers PkgConfig::DPDK)
target_compile_features(ker_dpdk_port PRIVATE c_std_11)
set_target_properties(ker_dpdk_port PROPERTIES POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
