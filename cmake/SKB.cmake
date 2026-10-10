find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(KER_SKB_IMPORT "${PROJECT_BINARY_DIR}/linux-skb")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/import-linux-skb.py"
    --linux "${KER_LINUX_DIR}"
    --manifest "${PROJECT_SOURCE_DIR}/src/compat/linux-skb-manifest.json"
    --out "${KER_SKB_IMPORT}"
    RESULT_VARIABLE ker_skb_import_result ERROR_VARIABLE ker_skb_import_error)
if(NOT ker_skb_import_result EQUAL 0)
    message(FATAL_ERROR "Linux skb import failed: ${ker_skb_import_error}")
endif()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/tools/import-linux-skb.py"
    "${PROJECT_SOURCE_DIR}/src/compat/linux-skb-manifest.json"
    "${KER_LINUX_DIR}/include/linux/skbuff.h" "${KER_LINUX_DIR}/net/core/skbuff.c"
    "${KER_LINUX_DIR}/include/linux/types.h" "${KER_LINUX_DIR}/include/linux/llist.h"
    "${KER_LINUX_DIR}/include/net/netmem.h" "${KER_LINUX_DIR}/include/linux/kconfig.h"
    "${KER_LINUX_DIR}/include/linux/kcov.h" "${KER_LINUX_DIR}/include/linux/stddef.h"
    "${KER_LINUX_DIR}/include/uapi/linux/stddef.h")
add_library(ker_skb_headers INTERFACE)
target_include_directories(ker_skb_headers SYSTEM INTERFACE "${KER_SKB_IMPORT}")
target_link_libraries(ker_skb_headers INTERFACE ker_port_headers PkgConfig::DPDK)
add_library(ker_skb_port OBJECT "${KER_SKB_IMPORT}/linux_skb.c" src/runtime/skb.c)
target_link_libraries(ker_skb_port PRIVATE ker_skb_headers)
target_compile_features(ker_skb_port PRIVATE c_std_11)
set_target_properties(ker_skb_port PROPERTIES POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
