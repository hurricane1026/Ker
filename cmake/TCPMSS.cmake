set(KER_TCP_MSS_IMPORT "${PROJECT_BINARY_DIR}/linux-tcp-mss")
set(KER_TCP_MSS_MANIFEST "${PROJECT_SOURCE_DIR}/src/compat/linux-tcp-mss-manifest.json")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/import-linux-tcp-mss.py"
    --linux "${KER_LINUX_DIR}" --manifest "${KER_TCP_MSS_MANIFEST}" --out "${KER_TCP_MSS_IMPORT}"
    RESULT_VARIABLE ker_tcp_mss_result ERROR_VARIABLE ker_tcp_mss_error)
if(NOT ker_tcp_mss_result EQUAL 0)
    message(FATAL_ERROR "Linux TCP MSS import failed: ${ker_tcp_mss_error}")
endif()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${KER_LINUX_DIR}/net/ipv4/tcp_input.c"
    "${KER_LINUX_DIR}/include/uapi/linux/tcp.h"
    "${KER_LINUX_DIR}/include/net/tcp.h"
    "${KER_TCP_MSS_MANIFEST}" "${PROJECT_SOURCE_DIR}/tools/import-linux-tcp-mss.py"
    "${PROJECT_SOURCE_DIR}/tools/import-linux-skb.py")
add_library(ker_tcp_mss_headers INTERFACE)
target_include_directories(ker_tcp_mss_headers SYSTEM INTERFACE "${KER_TCP_MSS_IMPORT}")
target_link_libraries(ker_tcp_mss_headers INTERFACE ker_port_headers)
add_library(ker_tcp_mss_port OBJECT "${KER_TCP_MSS_IMPORT}/linux_tcp_mss.c" src/runtime/tcp-mss.c)
target_link_libraries(ker_tcp_mss_port PRIVATE ker_tcp_mss_headers ker_eth_headers ker_tcp_view_port)
set_source_files_properties("${KER_TCP_MSS_IMPORT}/linux_tcp_mss.c" PROPERTIES COMPILE_OPTIONS -Wno-sign-compare)
target_compile_features(ker_tcp_mss_port PRIVATE c_std_11)
set_target_properties(ker_tcp_mss_port PROPERTIES POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
