add_executable(ker-checksum-test checksum.c)
target_link_libraries(ker-checksum-test PRIVATE ker::ker ker_port_headers ker_linux_port)
add_test(NAME checksum COMMAND ker-checksum-test)

add_executable(ker-timer-test timer.c)
target_link_libraries(ker-timer-test PRIVATE ker_port_headers ker_linux_port)
add_test(NAME timer COMMAND ker-timer-test)

add_executable(ker-refcount-test refcount.c)
target_link_libraries(ker-refcount-test PRIVATE ker_port_headers ker_linux_port Threads::Threads)
add_test(NAME refcount COMMAND ker-refcount-test)

if(KER_WITH_DPDK)
    add_executable(ker-dpdk-memory-test dpdk-memory.c)
    target_compile_definitions(ker-dpdk-memory-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-dpdk-memory-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME dpdk-memory COMMAND ker-dpdk-memory-test)
    add_executable(ker-worker-test worker.c)
    target_compile_definitions(ker-worker-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-worker-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME worker COMMAND ker-worker-test)
    set_tests_properties(worker PROPERTIES TIMEOUT 30)
    add_executable(ker-skb-test skb.c)
    target_compile_definitions(ker-skb-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-skb-test PRIVATE
        ker_skb_headers ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME skb COMMAND ker-skb-test)
    add_test(NAME skb-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/skb-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" ${DPDK_INCLUDE_DIRS})
    set_tests_properties(skb PROPERTIES TIMEOUT 30)
    set_tests_properties(dpdk-memory PROPERTIES TIMEOUT 30)
    list(JOIN DPDK_LIBRARY_DIRS ":" ker_dpdk_library_path)
    set_tests_properties(checksum timer refcount dpdk-memory skb worker PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
endif()
