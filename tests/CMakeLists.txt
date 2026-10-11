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
    add_executable(ker-ethernet-test ethernet.c)
    target_compile_definitions(ker-ethernet-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ethernet-test PRIVATE ker_eth_headers ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME ethernet COMMAND ker-ethernet-test)
    set_tests_properties(ethernet PROPERTIES TIMEOUT 30)
    add_test(NAME ethernet-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/ethernet-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-napi-test napi.c)
    target_compile_definitions(ker-napi-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-napi-test PRIVATE ker_napi_headers ker_napi_port ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME napi COMMAND ker-napi-test)
    set_tests_properties(napi PROPERTIES TIMEOUT 30)
    add_test(NAME napi-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/napi-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-receive-test receive.c)
    target_compile_definitions(ker-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-receive-test PRIVATE ker_receive_headers ker_receive_port ker_napi_port
        ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME receive COMMAND ker-receive-test)
    set_tests_properties(receive PROPERTIES TIMEOUT 30)
    add_test(NAME receive-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/receive-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}" "${KER_NAPI_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-arp-test arp.c)
    target_compile_definitions(ker-arp-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-test PRIVATE ker_arp_headers ker_arp_port ker_receive_headers
        ker_receive_port ker_napi_port ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME arp COMMAND ker-arp-test)
    set_tests_properties(arp PROPERTIES TIMEOUT 30)
    add_test(NAME arp-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/arp-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-address-test ipv4-address.c)
    target_compile_definitions(ker-address-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-address-test PRIVATE ker_address_headers ker_address_port ker_arp_headers
        ker_arp_port ker_receive_headers ker_receive_port ker_napi_port ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME ipv4-address COMMAND ker-address-test)
    set_tests_properties(ipv4-address PROPERTIES TIMEOUT 30)
    add_test(NAME address-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/address-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-neighbor-timer-test neighbor-timer.c)
    target_compile_definitions(ker-neighbor-timer-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-neighbor-timer-test PRIVATE ker_neighbor_timer_headers
        ker_neighbor_timer_port ker_timer_list_port ker_neighbor_port
        ker_address_port ker_arp_port ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME neighbor-timer COMMAND ker-neighbor-timer-test)
    set_tests_properties(neighbor-timer PROPERTIES TIMEOUT 30)
    add_test(NAME neighbor-timer-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/neighbor-timer-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}"
        "${KER_ADDR_IMPORT}" "${KER_NAPI_IMPORT}" "${KER_NEIGH_IMPORT}" "${KER_TIMER_LIST_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-neighbor-test neighbor.c)
    target_compile_definitions(ker-neighbor-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-neighbor-test PRIVATE ker_neighbor_headers ker_neighbor_port ker_receive_headers
        ker_address_port ker_arp_headers ker_arp_port ker_receive_port ker_napi_port ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME neighbor COMMAND ker-neighbor-test)
    set_tests_properties(neighbor PROPERTIES TIMEOUT 30)
    add_test(NAME neighbor-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/neighbor-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}"
        "${KER_ADDR_IMPORT}" "${KER_NAPI_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-arp-receive-test arp-receive.c)
    target_compile_definitions(ker-arp-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-receive-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_address_port ker_arp_port ker_receive_port ker_napi_port ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME arp-receive COMMAND ker-arp-receive-test)
    set_tests_properties(arp-receive PROPERTIES TIMEOUT 30)
    add_test(NAME arp-receive-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/arp-receive-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}"
        "${KER_NAPI_IMPORT}" "${KER_RX_IMPORT}" "${KER_ARP_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-timer-list-test timer-list.c)
    target_compile_definitions(ker-timer-list-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-timer-list-test PRIVATE ker_timer_list_headers ker_timer_list_port
        ker_linux_port ker_dpdk_port Threads::Threads)
    add_test(NAME timer-list COMMAND ker-timer-list-test)
    set_tests_properties(timer-list PROPERTIES TIMEOUT 30)
    add_test(NAME timer-list-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/timer-list-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-skb-queue-test skb-queue.c)
    target_compile_definitions(ker-skb-queue-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-skb-queue-test PRIVATE ker_neighbor_headers ker_neighbor_port
        ker_address_port ker_napi_port ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME skb-queue COMMAND ker-skb-queue-test)
    set_tests_properties(skb-queue PROPERTIES TIMEOUT 30)
    add_test(NAME skb-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/skb-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" ${DPDK_INCLUDE_DIRS})
    set_tests_properties(skb PROPERTIES TIMEOUT 30)
    set_tests_properties(dpdk-memory PROPERTIES TIMEOUT 30)
    list(JOIN DPDK_LIBRARY_DIRS ":" ker_dpdk_library_path)
    set_tests_properties(checksum timer refcount dpdk-memory skb worker ethernet napi receive arp ipv4-address neighbor arp-receive skb-queue timer-list PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
endif()
