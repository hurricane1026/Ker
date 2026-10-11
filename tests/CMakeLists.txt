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
    add_executable(ker-fstack-ipv4-ingress-test fstack-ipv4-ingress.c)
    target_include_directories(ker-fstack-ipv4-ingress-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-ipv4-ingress-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-ipv4-ingress-test PRIVATE ker_ipv4_view_port ker_eth_headers ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-ipv4-ingress-validation COMMAND ker-fstack-ipv4-ingress-test)
    set_tests_properties(fstack-ipv4-ingress-validation PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-udp-ingress-test fstack-udp-ingress.c)
    target_include_directories(ker-fstack-udp-ingress-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-udp-ingress-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-udp-ingress-test PRIVATE ker_udp_view_port ker_ipv4_view_port ker_eth_headers ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-udp-ingress-validation COMMAND ker-fstack-udp-ingress-test)
    set_tests_properties(fstack-udp-ingress-validation PROPERTIES TIMEOUT 30)
    add_test(NAME fstack-udp-minimal-boundaries COMMAND ker-fstack-udp-ingress-test minimal-boundaries)
    set_tests_properties(fstack-udp-minimal-boundaries PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-tcp-ingress-test fstack-tcp-ingress.c)
    target_include_directories(ker-fstack-tcp-ingress-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-tcp-ingress-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-tcp-ingress-test PRIVATE ker_tcp_view_port ker_ipv4_view_port ker_eth_headers ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-tcp-ingress-validation COMMAND ker-fstack-tcp-ingress-test)
    set_tests_properties(fstack-tcp-ingress-validation PROPERTIES TIMEOUT 30)
    add_executable(ker-transport-receive-test transport-receive.c)
    target_include_directories(ker-transport-receive-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-transport-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-transport-receive-test PRIVATE ker_transport_receive_port
        ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_receive_port
        ker_receive_headers ker_eth_headers ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME transport-receive COMMAND ker-transport-receive-test)
    set_tests_properties(transport-receive PROPERTIES TIMEOUT 30)
    add_executable(ker-tx-export-test tx-export.c)
    target_include_directories(ker-tx-export-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tx-export-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tx-export-test PRIVATE ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_udp_create_port ker_tx_export_port Threads::Threads)
    add_test(NAME tx-export COMMAND ker-tx-export-test)
    set_tests_properties(tx-export PROPERTIES TIMEOUT 30)
    add_executable(ker-tx-export-chain-test tx-export-chain.c)
    target_include_directories(ker-tx-export-chain-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tx-export-chain-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tx-export-chain-test PRIVATE ker_neighbor_headers ker_timer_list_port
        ker_receive_headers ker_eth_headers ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port
        ker_transport_receive_port ker_receive_port ker_eth_port ker_linux_port ker_dpdk_port
        ker_address_port ker_neighbor_port ker_skb_port ker_udp_create_port ker_tcp_create_port
        ker_tx_export_port Threads::Threads)
    add_test(NAME tx-export-chain COMMAND ker-tx-export-chain-test)
    set_tests_properties(tx-export-chain PROPERTIES TIMEOUT 30)
    add_executable(ker-tx-ring-test tx-ring.c)
    target_include_directories(ker-tx-ring-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tx-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tx-ring-test PRIVATE ker_tx_ring_port ker_tx_export_port
        ker_skb_headers ker_neighbor_headers ker_receive_headers ker_eth_headers
        ker_neighbor_port ker_address_port ker_skb_port ker_eth_port ker_receive_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_transport_receive_port
        ker_udp_create_port ker_tcp_create_port ker_timer_list_port ker_linux_port
        ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME tx-ring COMMAND ker-tx-ring-test)
    set_tests_properties(tx-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-chain-export-test fstack-chain-export.c)
    target_include_directories(ker-fstack-chain-export-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-chain-export-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-chain-export-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_address_port ker_skb_port
        ker_eth_port ker_dpdk_port ker_linux_port ker_udp_create_port ker_tcp_create_port
        ker_transport_receive_port ker_receive_port ker_receive_headers ker_ipv4_view_port
        ker_udp_view_port ker_tcp_view_port ker_neighbor_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-chain-export COMMAND ker-fstack-chain-export-test)
    set_tests_properties(fstack-chain-export PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-chain-checksum-test fstack-chain-checksum.c)
    target_include_directories(ker-fstack-chain-checksum-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-chain-checksum-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-chain-checksum-test PRIVATE ker_skb_headers ker_eth_headers
        ker_receive_headers ker_neighbor_headers ker_linux_port ker_dpdk_port ker_skb_port ker_eth_port
        ker_receive_port ker_address_port ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port
        ker_transport_receive_port ker_udp_create_port ker_tcp_create_port ker_neighbor_port
        ker_tx_export_port Threads::Threads)
    add_test(NAME fstack-chain-checksum COMMAND ker-fstack-chain-checksum-test)
    set_tests_properties(fstack-chain-checksum PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-options-test tcp-options.c)
    target_include_directories(ker-tcp-options-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-options-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-options-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    add_test(NAME tcp-options COMMAND ker-tcp-options-test)
    set_tests_properties(tcp-options PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-create-test tcp-create.c)
    target_include_directories(ker-tcp-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-create-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    add_test(NAME tcp-create COMMAND ker-tcp-create-test)
    set_tests_properties(tcp-create PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-neighbor-create-test tcp-neighbor-create.c)
    target_include_directories(ker-tcp-neighbor-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-neighbor-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-neighbor-create-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers
        ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port
        ker_tx_export_port ker_tcp_create_port ker_tcp_neighbor_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port
        ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    add_test(NAME tcp-neighbor-create COMMAND ker-tcp-neighbor-create-test)
    set_tests_properties(tcp-neighbor-create PROPERTIES TIMEOUT 30)
    add_executable(ker-udp-create-test udp-create.c)
    target_include_directories(ker-udp-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-udp-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-create-test PRIVATE ker_udp_create_port ker_transport_receive_port
        ker_udp_view_port ker_tcp_view_port ker_ipv4_view_port ker_receive_port ker_receive_headers ker_eth_headers
        ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME udp-create COMMAND ker-udp-create-test)
    set_tests_properties(udp-create PROPERTIES TIMEOUT 30)
    add_executable(ker-udp-neighbor-create-test udp-neighbor-create.c)
    target_include_directories(ker-udp-neighbor-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-udp-neighbor-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-neighbor-create-test PRIVATE ker_neighbor_headers ker_address_port ker_neighbor_port
        ker_udp_neighbor_create_port ker_udp_create_port ker_transport_receive_port ker_udp_view_port ker_tcp_view_port ker_ipv4_view_port
        ker_receive_port ker_receive_headers ker_eth_headers ker_eth_port ker_linux_port ker_dpdk_port
        ker_skb_port ker_tx_export_port Threads::Threads)
    add_test(NAME udp-neighbor-create COMMAND ker-udp-neighbor-create-test)
    set_tests_properties(udp-neighbor-create PROPERTIES TIMEOUT 30)
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
    target_include_directories(ker-neighbor-timer-test PRIVATE "${KER_ARP_PROBE_IMPORT}" "${KER_NEIGH_UPDATE_IMPORT}" "${KER_NEIGH_EVENT_SEND_IMPORT}")
    target_compile_definitions(ker-neighbor-timer-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-neighbor-timer-test PRIVATE ker_neighbor_timer_headers
        ker_neighbor_timer_port ker_timer_list_port ker_neighbor_port
        ker_neighbor_update_headers ker_neighbor_update_port ker_neighbor_event_send_headers ker_neighbor_event_send_port ker_address_port ker_arp_headers ker_arp_port ker_arp_probe_port ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME neighbor-timer COMMAND ker-neighbor-timer-test)
    set_tests_properties(neighbor-timer PROPERTIES TIMEOUT 30)
    add_test(NAME neighbor-timer-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/neighbor-timer-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}"
        "${KER_ADDR_IMPORT}" "${KER_NAPI_IMPORT}" "${KER_NEIGH_IMPORT}" "${KER_TIMER_LIST_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_test(NAME arp-probe-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/arp-probe-import.py" "${KER_LINUX_DIR}"
        "${KER_ARP_PROBE_MANIFEST}" "${KER_ARP_PROBE_IMPORT}"
        "${PROJECT_SOURCE_DIR}/tools/import-linux-arp-probe.py")
    add_test(NAME neighbor-update-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/neighbor-update-import.py" "${KER_LINUX_DIR}"
        "${KER_NEIGH_UPDATE_MANIFEST}" "${KER_NEIGH_UPDATE_IMPORT}"
        "${PROJECT_SOURCE_DIR}/tools/import-linux-neighbor-update.py")
    add_test(NAME neighbor-event-send-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/neighbor-event-send-import.py" "${KER_LINUX_DIR}"
        "${KER_NEIGH_EVENT_SEND_MANIFEST}" "${KER_NEIGH_EVENT_SEND_IMPORT}"
        "${PROJECT_SOURCE_DIR}/tools/import-linux-neighbor-event-send.py")
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
    target_include_directories(ker-arp-receive-test PRIVATE "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-arp-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-receive-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_arp_neighbor_feedback_port ker_neighbor_timer_headers ker_neighbor_timer_port
        ker_neighbor_update_headers ker_neighbor_update_port ker_neighbor_event_send_port ker_timer_list_port ker_neighbor_port
        ker_address_port ker_arp_port ker_receive_port ker_napi_port ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME arp-receive COMMAND ker-arp-receive-test)
    set_tests_properties(arp-receive PROPERTIES TIMEOUT 30)
    add_test(NAME arp-receive-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/arp-receive-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}"
        "${KER_NAPI_IMPORT}" "${KER_RX_IMPORT}" "${KER_ARP_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-fstack-arp-chain-test fstack-arp-chain.c)
    target_include_directories(ker-fstack-arp-chain-test PRIVATE "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-fstack-arp-chain-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-arp-chain-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_arp_neighbor_feedback_port ker_neighbor_timer_headers ker_neighbor_timer_port
        ker_neighbor_update_headers ker_neighbor_update_port ker_neighbor_event_send_port ker_timer_list_port
        ker_neighbor_port ker_address_port ker_arp_port ker_receive_port ker_napi_port ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME fstack-arp-chain-feedback COMMAND ker-fstack-arp-chain-test)
    set_tests_properties(fstack-arp-chain-feedback PROPERTIES TIMEOUT 30)
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
    target_include_directories(ker-skb-queue-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-skb-queue-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-skb-queue-test PRIVATE ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_neighbor_headers ker_neighbor_port
        ker_address_port ker_napi_port ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME skb-queue COMMAND ker-skb-queue-test)
    set_tests_properties(skb-queue PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-adapted-test fstack-adapted.c)
    target_compile_definitions(ker-fstack-adapted-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-adapted-test PRIVATE ker_neighbor_headers ker_neighbor_port
        ker_receive_headers ker_receive_port ker_address_port ker_napi_port ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    foreach(fstack_case mbuf-release clock-monotonic empty-export null-context packet-export
            multiseg-boundary queue-isolation queue-full-ownership export-exhaustion-retry
            offload-metadata-rejection headroom-export multiseg-copy multiseg-ethernet-ingress
            software-checksum-completion)
        add_test(NAME fstack-${fstack_case} COMMAND ker-fstack-adapted-test ${fstack_case})
        set_tests_properties(fstack-${fstack_case} PROPERTIES TIMEOUT 30)
        list(APPEND ker_fstack_tests fstack-${fstack_case})
    endforeach()
    add_test(NAME skb-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/skb-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" ${DPDK_INCLUDE_DIRS})
    set_tests_properties(skb PROPERTIES TIMEOUT 30)
    set_tests_properties(dpdk-memory PROPERTIES TIMEOUT 30)
    list(JOIN DPDK_LIBRARY_DIRS ":" ker_dpdk_library_path)
    set_tests_properties(checksum timer refcount dpdk-memory skb worker ethernet fstack-ipv4-ingress-validation fstack-udp-ingress-validation fstack-udp-minimal-boundaries fstack-tcp-ingress-validation transport-receive fstack-chain-export fstack-chain-checksum udp-create udp-neighbor-create tcp-create tcp-neighbor-create tcp-options napi receive arp ipv4-address neighbor-timer neighbor arp-receive fstack-arp-chain-feedback skb-queue timer-list arp-probe-import neighbor-update-import tx-export tx-export-chain tx-ring ${ker_fstack_tests} PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
endif()
