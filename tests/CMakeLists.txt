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
    add_executable(ker-ipv4-fields-test ipv4-fields.c)
    target_include_directories(ker-ipv4-fields-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-ipv4-fields-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-ipv4-fields-test PRIVATE ker_skb_headers ker_eth_headers
        ker_udp_create_port ker_tcp_create_port ker_icmp_echo_create_port
        ker_linux_port ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME ipv4-fields COMMAND ker-ipv4-fields-test)
    set_tests_properties(ipv4-fields PROPERTIES TIMEOUT 30)
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
    add_executable(ker-flow-test flow.c)
    target_compile_definitions(ker-flow-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow COMMAND ker-flow-test)
    set_tests_properties(flow PROPERTIES TIMEOUT 30)
    add_executable(ker-flow-chain-test flow-chain.c)
    target_compile_definitions(ker-flow-chain-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-chain-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow-chain COMMAND ker-flow-chain-test)
    set_tests_properties(flow-chain PROPERTIES TIMEOUT 30)
    add_executable(ker-flow-ip-options-test flow-ip-options.c)
    target_compile_definitions(ker-flow-ip-options-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-ip-options-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow-ip-options COMMAND ker-flow-ip-options-test)
    set_tests_properties(flow-ip-options PROPERTIES TIMEOUT 30)
    add_executable(ker-flow-icmpv4-test flow-icmpv4.c)
    target_compile_definitions(ker-flow-icmpv4-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-icmpv4-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow-icmpv4 COMMAND ker-flow-icmpv4-test)
    set_tests_properties(flow-icmpv4 PROPERTIES TIMEOUT 30)
    add_executable(ker-flow-buckets-test flow-buckets.c)
    target_compile_definitions(ker-flow-buckets-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-buckets-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow-buckets COMMAND ker-flow-buckets-test)
    set_tests_properties(flow-buckets PROPERTIES TIMEOUT 60)
    add_executable(ker-flow-steering-test flow-steering.c)
    target_compile_definitions(ker-flow-steering-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-steering-test PRIVATE
        ker_port_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow-matrix COMMAND ker-flow-steering-test --matrix)
    add_test(NAME flow-multicore COMMAND ker-flow-steering-test --multicore)
    set_tests_properties(flow-matrix PROPERTIES TIMEOUT 30)
    set_tests_properties(flow-multicore PROPERTIES TIMEOUT 45 SKIP_RETURN_CODE 77)
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
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_receive_port
        ker_receive_headers ker_eth_headers ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_executable(ker-fstack-flow-receive-test fstack-flow-receive.c)
    target_include_directories(ker-fstack-flow-receive-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-flow-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-flow-receive-test PRIVATE ker_transport_receive_port
        ker_flow_ring_port ker_tx_ring_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_receive_port
        ker_receive_headers ker_eth_headers ker_skb_headers ker_neighbor_headers ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME fstack-flow-receive COMMAND ker-fstack-flow-receive-test)
    set_tests_properties(fstack-flow-receive PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-flow-owner-receive-test fstack-flow-owner-receive.c)
    target_include_directories(ker-fstack-flow-owner-receive-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-flow-owner-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-flow-owner-receive-test PRIVATE ker_flow_receive_port
        ker_transport_receive_port ker_flow_ring_port ker_rx_ring_port ker_tx_ring_port ker_receive_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port
        ker_receive_headers ker_eth_headers ker_skb_headers ker_neighbor_headers ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port ker_address_port ker_neighbor_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-flow-owner-receive COMMAND ker-fstack-flow-owner-receive-test)
    set_tests_properties(fstack-flow-owner-receive PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-flow-concurrent-receive-test fstack-flow-concurrent-receive.c)
    target_include_directories(ker-fstack-flow-concurrent-receive-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-flow-concurrent-receive-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-flow-concurrent-receive-test PRIVATE ker_transport_receive_port
        ker_flow_ring_port ker_tx_ring_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port
        ker_receive_port ker_receive_headers ker_eth_headers ker_skb_headers ker_neighbor_headers ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port ker_address_port ker_neighbor_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-flow-concurrent-receive COMMAND ker-fstack-flow-concurrent-receive-test)
    set_tests_properties(fstack-flow-concurrent-receive PROPERTIES TIMEOUT 45 SKIP_RETURN_CODE 77)
    add_test(NAME transport-receive COMMAND ker-transport-receive-test)
    set_tests_properties(transport-receive PROPERTIES TIMEOUT 30)
    add_executable(ker-icmp-echo-test icmp-echo.c)
    target_include_directories(ker-icmp-echo-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-icmp-echo-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-icmp-echo-test PRIVATE ker_icmpv4_create_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_icmp_echo_create_port
        ker_ipv4_view_port ker_eth_headers ker_skb_headers ker_eth_port ker_linux_port ker_dpdk_port
        ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME icmp-echo COMMAND ker-icmp-echo-test)
    set_tests_properties(icmp-echo PROPERTIES TIMEOUT 30)
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
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_eth_port ker_linux_port ker_dpdk_port
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
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port
        ker_udp_create_port ker_tcp_create_port ker_timer_list_port ker_linux_port
        ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME tx-ring COMMAND ker-tx-ring-test)
    set_tests_properties(tx-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-flow-ring-test flow-ring.c)
    target_include_directories(ker-flow-ring-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-flow-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-flow-ring-test PRIVATE ker_flow_ring_port ker_tx_ring_port
        ker_port_headers ker_skb_headers ker_neighbor_headers ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME flow-ring COMMAND ker-flow-ring-test)
    set_tests_properties(flow-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-rx-ring-test rx-ring.c)
    target_include_directories(ker-rx-ring-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-rx-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-rx-ring-test PRIVATE ker_rx_ring_port ker_skb_headers ker_neighbor_headers
        ker_receive_headers ker_eth_headers ker_tx_export_port ker_tx_ring_port
        ker_skb_port ker_eth_port ker_receive_port ker_neighbor_port ker_address_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port
        ker_udp_create_port ker_tcp_create_port ker_icmp_echo_create_port ker_timer_list_port ker_linux_port
        ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME rx-ring COMMAND ker-rx-ring-test)
    set_tests_properties(rx-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-cross-worker-ring-test cross-worker-ring.c)
    target_include_directories(ker-cross-worker-ring-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-cross-worker-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-cross-worker-ring-test PRIVATE ker_rx_ring_port ker_skb_headers
        ker_neighbor_headers ker_receive_headers ker_eth_headers ker_tx_export_port ker_tx_ring_port
        ker_skb_port ker_eth_port ker_receive_port ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_udp_create_port ker_tcp_create_port
        ker_neighbor_port ker_address_port ker_timer_list_port ker_linux_port ker_dpdk_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME cross-worker-ring COMMAND ker-cross-worker-ring-test)
    set_tests_properties(cross-worker-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-concurrent-ring-test fstack-concurrent-ring.c)
    target_include_directories(ker-fstack-concurrent-ring-test PRIVATE "${PROJECT_SOURCE_DIR}/src" "${KER_ADDR_IMPORT}")
    target_compile_definitions(ker-fstack-concurrent-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-concurrent-ring-test PRIVATE ker_rx_ring_port ker_skb_headers
        ker_neighbor_headers ker_receive_headers ker_eth_headers ker_tx_export_port ker_tx_ring_port
        ker_skb_port ker_eth_port ker_receive_port ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_icmp_echo_create_port ker_transport_receive_port ker_udp_create_port ker_tcp_create_port
        ker_udp_configured_create_port ker_tcp_configured_create_port ker_icmp_echo_configured_create_port
        ker_neighbor_port ker_address_port ker_timer_list_port ker_linux_port ker_dpdk_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-concurrent-ring COMMAND ker-fstack-concurrent-ring-test)
    set_tests_properties(fstack-concurrent-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-chain-export-test fstack-chain-export.c)
    target_include_directories(ker-fstack-chain-export-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-chain-export-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-chain-export-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_address_port ker_skb_port
        ker_eth_port ker_dpdk_port ker_linux_port ker_udp_create_port ker_tcp_create_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_ipv4_view_port
        ker_udp_view_port ker_tcp_view_port ker_neighbor_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-chain-export COMMAND ker-fstack-chain-export-test)
    set_tests_properties(fstack-chain-export PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-chain-checksum-test fstack-chain-checksum.c)
    target_include_directories(ker-fstack-chain-checksum-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-fstack-chain-checksum-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-chain-checksum-test PRIVATE ker_skb_headers ker_eth_headers
        ker_receive_headers ker_neighbor_headers ker_linux_port ker_dpdk_port ker_skb_port ker_eth_port
        ker_receive_port ker_address_port ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_udp_create_port ker_tcp_create_port ker_neighbor_port
        ker_tx_export_port Threads::Threads)
    add_test(NAME fstack-chain-checksum COMMAND ker-fstack-chain-checksum-test)
    set_tests_properties(fstack-chain-checksum PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-options-test tcp-options.c)
    target_include_directories(ker-tcp-options-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-options-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-options-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    add_test(NAME tcp-options COMMAND ker-tcp-options-test)
    set_tests_properties(tcp-options PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-create-test tcp-create.c)
    target_include_directories(ker-tcp-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-create-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    add_test(NAME tcp-create COMMAND ker-tcp-create-test)
    set_tests_properties(tcp-create PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-ip-options-test tcp-ip-options.c)
    target_include_directories(ker-tcp-ip-options-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-ip-options-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-ip-options-test PRIVATE ker_skb_headers ker_eth_headers
        ker_receive_headers ker_neighbor_headers ker_tcp_create_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_receive_port ker_skb_port
        ker_eth_port ker_neighbor_port ker_address_port ker_tx_export_port ker_tx_ring_port
        ker_rx_ring_port ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME tcp-ip-options COMMAND ker-tcp-ip-options-test)
    set_tests_properties(tcp-ip-options PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-neighbor-create-test tcp-neighbor-create.c)
    target_include_directories(ker-tcp-neighbor-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-neighbor-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-neighbor-create-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers
        ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port
        ker_tx_export_port ker_tcp_create_port ker_tcp_neighbor_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port
        ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    add_test(NAME tcp-neighbor-create COMMAND ker-tcp-neighbor-create-test)
    set_tests_properties(tcp-neighbor-create PROPERTIES TIMEOUT 30)
    add_executable(ker-udp-create-test udp-create.c)
    target_include_directories(ker-udp-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-udp-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-create-test PRIVATE ker_udp_create_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port
        ker_udp_view_port ker_tcp_view_port ker_ipv4_view_port ker_receive_port ker_receive_headers ker_eth_headers
        ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME udp-create COMMAND ker-udp-create-test)
    set_tests_properties(udp-create PROPERTIES TIMEOUT 30)
    add_executable(ker-udp-io-test udp-io.c)
    target_include_directories(ker-udp-io-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-udp-io-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-io-test PRIVATE ker_arp_headers
        ker_neighbor_timer_headers ker_receive_headers ker_udp_io_port ker_udp_error_port
        ker_udp_endpoint_port ker_icmpv4_service_port ker_transport_receive_port ker_udp_view_port
        ker_icmpv4_create_port ker_icmpv4_view_port ker_icmpv4_pmtu_port
        ker_icmp_echo_view_port ker_tcp_view_port ker_ipv4_view_port
        ker_receive_port ker_neighbor_timer_port ker_neighbor_update_port
        ker_neighbor_event_send_port ker_timer_list_port ker_neighbor_port
        ker_address_port ker_arp_port ker_arp_probe_port ker_udp_create_port
        ker_tx_export_port ker_tx_ring_port ker_rx_ring_port
        ker_eth_port ker_skb_port ker_linux_port ker_dpdk_port PkgConfig::DPDK
        Threads::Threads)
    add_test(NAME udp-io COMMAND ker-udp-io-test)
    set_tests_properties(udp-io PROPERTIES TIMEOUT 30)
    add_executable(ker-udp-flow-test udp-flow.c)
    target_include_directories(ker-udp-flow-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-udp-flow-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-flow-test PRIVATE ker_arp_rx_headers ker_skb_headers ker_neighbor_headers
        ker_neighbor_timer_headers ker_neighbor_update_headers ker_udp_io_port ker_udp_error_port ker_icmpv4_pmtu_port
        ker_udp_flow_port ker_udp_endpoint_port ker_icmpv4_service_port
        ker_icmpv4_create_port ker_icmpv4_view_port ker_icmp_echo_view_port
        ker_tcp_view_port ker_arp_rx_port ker_transport_receive_port
        ker_udp_view_port ker_ipv4_view_port
        ker_receive_port ker_neighbor_timer_port ker_neighbor_update_port
        ker_neighbor_event_send_port ker_arp_neighbor_feedback_port ker_arp_probe_port
        ker_arp_responder_port ker_timer_list_port ker_neighbor_port ker_address_port
        ker_arp_port ker_udp_create_port ker_tx_export_port ker_tx_ring_port
        ker_rx_ring_port ker_eth_port ker_skb_port ker_linux_port ker_dpdk_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME udp-flow COMMAND ker-udp-flow-test)
    set_tests_properties(udp-flow PROPERTIES TIMEOUT 45 SKIP_RETURN_CODE 77)
    add_executable(ker-udp-configured-create-test udp-configured-create.c)
    target_include_directories(ker-udp-configured-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src" "${KER_ADDR_IMPORT}")
    target_compile_definitions(ker-udp-configured-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-configured-create-test PRIVATE ker_skb_headers ker_address_headers
        ker_udp_configured_create_port ker_udp_create_port ker_address_port
        ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME udp-configured-create COMMAND ker-udp-configured-create-test)
    set_tests_properties(udp-configured-create PROPERTIES TIMEOUT 30)
    add_executable(ker-tcp-configured-create-test tcp-configured-create.c)
    target_include_directories(ker-tcp-configured-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src" "${KER_ADDR_IMPORT}")
    target_compile_definitions(ker-tcp-configured-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-configured-create-test PRIVATE ker_skb_headers ker_address_headers
        ker_tcp_configured_create_port ker_tcp_create_port ker_address_port
        ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME tcp-configured-create COMMAND ker-tcp-configured-create-test)
    set_tests_properties(tcp-configured-create PROPERTIES TIMEOUT 30)
    add_executable(ker-icmp-echo-configured-create-test icmp-echo-configured-create.c)
    target_include_directories(ker-icmp-echo-configured-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src" "${KER_ADDR_IMPORT}")
    target_compile_definitions(ker-icmp-echo-configured-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-icmp-echo-configured-create-test PRIVATE ker_skb_headers ker_address_headers
        ker_icmp_echo_configured_create_port ker_icmp_echo_create_port ker_udp_configured_create_port
        ker_udp_create_port ker_tcp_configured_create_port ker_tcp_create_port ker_address_port
        ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME icmp-echo-configured-create COMMAND ker-icmp-echo-configured-create-test)
    set_tests_properties(icmp-echo-configured-create PROPERTIES TIMEOUT 30)
    add_executable(ker-udp-ip-options-test udp-ip-options.c)
    target_include_directories(ker-udp-ip-options-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-udp-ip-options-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-ip-options-test PRIVATE ker_skb_headers ker_eth_headers
        ker_receive_headers ker_neighbor_headers ker_udp_create_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_receive_port ker_skb_port
        ker_eth_port ker_neighbor_port ker_address_port ker_tx_export_port ker_tx_ring_port
        ker_linux_port ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME udp-ip-options COMMAND ker-udp-ip-options-test)
    set_tests_properties(udp-ip-options PROPERTIES TIMEOUT 30)
    add_executable(ker-udp-neighbor-create-test udp-neighbor-create.c)
    target_link_libraries(ker-udp-neighbor-create-test PRIVATE ker_icmp_echo_neighbor_create_port ker_icmp_echo_create_port
        ker_tcp_neighbor_create_port ker_tcp_create_port)
    target_include_directories(ker-udp-neighbor-create-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-udp-neighbor-create-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-neighbor-create-test PRIVATE ker_neighbor_headers ker_address_port ker_neighbor_port
        ker_udp_neighbor_create_port ker_udp_create_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_udp_view_port ker_tcp_view_port ker_ipv4_view_port
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
    add_executable(ker-arp-configured-test arp-configured.c)
    target_include_directories(ker-arp-configured-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-arp-configured-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-configured-test PRIVATE ker_arp_headers ker_arp_port
        ker_address_headers ker_address_port ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port
        PkgConfig::DPDK Threads::Threads)
    add_test(NAME arp-configured COMMAND ker-arp-configured-test)
    set_tests_properties(arp-configured PROPERTIES TIMEOUT 30)
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
    add_executable(ker-icmpv4-pmtu-test icmpv4-pmtu.c)
    target_include_directories(ker-icmpv4-pmtu-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-icmpv4-pmtu-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-icmpv4-pmtu-test PRIVATE ker_icmpv4_pmtu_port ker_icmpv4_service_port
        ker_icmpv4_create_port ker_transport_receive_port ker_receive_port ker_icmpv4_view_port
        ker_udp_view_port ker_tcp_view_port ker_icmp_echo_view_port
        ker_receive_headers ker_eth_headers ker_ipv4_view_port ker_neighbor_timer_headers
        ker_neighbor_timer_port ker_timer_list_port
        ker_neighbor_port ker_neighbor_update_headers ker_neighbor_update_port
        ker_neighbor_event_send_headers ker_neighbor_event_send_port ker_address_port ker_arp_headers
        ker_arp_port ker_arp_probe_port ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port
        ker_udp_create_port ker_udp_configured_create_port ker_tx_export_port Threads::Threads)
    add_test(NAME icmpv4-pmtu COMMAND ker-icmpv4-pmtu-test)
    set_tests_properties(icmpv4-pmtu PROPERTIES TIMEOUT 30)
    add_executable(ker-udp-error-test udp-error.c)
    target_include_directories(ker-udp-error-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-udp-error-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-error-test PRIVATE ker_udp_error_port ker_udp_io_port ker_udp_endpoint_port
        ker_icmpv4_pmtu_port ker_icmpv4_service_port ker_transport_receive_port
        ker_icmpv4_create_port ker_receive_port ker_icmpv4_view_port ker_udp_view_port ker_tcp_view_port
        ker_icmp_echo_view_port ker_receive_headers ker_eth_headers ker_ipv4_view_port
        ker_neighbor_timer_headers ker_neighbor_timer_port ker_timer_list_port
        ker_neighbor_headers ker_neighbor_port ker_neighbor_update_headers
        ker_neighbor_update_port ker_neighbor_event_send_headers ker_neighbor_event_send_port
        ker_address_port ker_arp_headers ker_arp_port ker_arp_probe_port ker_eth_port
        ker_linux_port ker_dpdk_port ker_skb_port ker_udp_create_port
        ker_udp_configured_create_port ker_tx_export_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME udp-error COMMAND ker-udp-error-test)
    set_tests_properties(udp-error PROPERTIES TIMEOUT 30)
    add_executable(ker-neighbor-timer-test neighbor-timer.c)
    target_include_directories(ker-neighbor-timer-test PRIVATE "${KER_ARP_PROBE_IMPORT}" "${KER_NEIGH_UPDATE_IMPORT}" "${KER_NEIGH_EVENT_SEND_IMPORT}")
    target_compile_definitions(ker-neighbor-timer-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-neighbor-timer-test PRIVATE ker_neighbor_timer_headers
        ker_neighbor_timer_port ker_timer_list_port ker_neighbor_port
        ker_neighbor_update_headers ker_neighbor_update_port ker_neighbor_event_send_headers ker_neighbor_event_send_port ker_address_port ker_arp_headers ker_arp_port ker_arp_probe_port ker_eth_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    target_link_libraries(ker-neighbor-timer-test PRIVATE ker_udp_create_port ker_udp_configured_create_port ker_tx_export_port)
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
    add_test(NAME neighbor-output-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/neighbor-output-import.py" "${KER_LINUX_DIR}"
        "${KER_NEIGH_OUTPUT_MANIFEST}" "${KER_NEIGH_OUTPUT_IMPORT}"
        "${PROJECT_SOURCE_DIR}/tools/import-linux-neighbor-output.py")
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
        ker_address_port ker_arp_port ker_receive_port ker_napi_port ker_eth_port ker_tx_export_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME arp-receive COMMAND ker-arp-receive-test)
    set_tests_properties(arp-receive PROPERTIES TIMEOUT 30)
    add_test(NAME arp-receive-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/arp-receive-import.py" "${PROJECT_SOURCE_DIR}"
        "${CMAKE_C_COMPILER}" "${KER_LINUX_INCLUDE}" "${KER_SKB_IMPORT}" "${KER_ETH_IMPORT}"
        "${KER_NAPI_IMPORT}" "${KER_RX_IMPORT}" "${KER_ARP_IMPORT}" ${DPDK_INCLUDE_DIRS})
    add_executable(ker-fstack-arp-chain-test fstack-arp-chain.c)
    target_include_directories(ker-fstack-arp-chain-test PRIVATE "${KER_NEIGH_UPDATE_IMPORT}" "${KER_ARP_PROBE_IMPORT}")
    target_compile_definitions(ker-fstack-arp-chain-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-arp-chain-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_arp_neighbor_feedback_port ker_neighbor_timer_headers ker_neighbor_timer_port
        ker_neighbor_update_headers ker_neighbor_update_port ker_neighbor_event_send_port ker_timer_list_port
        ker_neighbor_port ker_address_port ker_arp_port ker_receive_port ker_napi_port ker_eth_port ker_tx_export_port
        ker_arp_probe_port ker_udp_create_port ker_udp_configured_create_port
        ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME fstack-arp-chain-feedback COMMAND ker-fstack-arp-chain-test)
    set_tests_properties(fstack-arp-chain-feedback PROPERTIES TIMEOUT 30)
    add_executable(ker-arp-ring-test arp-ring.c)
    target_include_directories(ker-arp-ring-test PRIVATE "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-arp-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-ring-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_arp_neighbor_feedback_port ker_neighbor_timer_headers ker_neighbor_timer_port
        ker_neighbor_update_headers ker_neighbor_update_port ker_neighbor_event_send_port ker_timer_list_port
        ker_neighbor_port ker_address_port ker_arp_port ker_receive_port ker_napi_port ker_eth_port
        ker_rx_ring_port ker_tx_export_port ker_tx_ring_port ker_linux_port ker_dpdk_port ker_skb_port Threads::Threads)
    add_test(NAME arp-ring COMMAND ker-arp-ring-test)
    set_tests_properties(arp-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-arp-responder-test arp-responder.c)
    target_include_directories(ker-arp-responder-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-arp-responder-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-responder-test PRIVATE ker_arp_rx_headers ker_arp_rx_port ker_arp_responder_port ker_neighbor_headers
        ker_eth_headers ker_eth_port ker_address_port ker_arp_port ker_receive_port ker_transport_receive_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port
        ker_neighbor_timer_headers ker_neighbor_timer_port ker_neighbor_update_headers ker_neighbor_update_port
        ker_neighbor_event_send_port ker_timer_list_port ker_arp_neighbor_feedback_port ker_arp_probe_port
        ker_neighbor_port ker_rx_ring_port ker_tx_export_port ker_tx_ring_port ker_udp_configured_create_port
        ker_udp_create_port ker_linux_port ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME arp-responder COMMAND ker-arp-responder-test)
    set_tests_properties(arp-responder PROPERTIES TIMEOUT 30)
    add_executable(ker-fstack-icmp-echo-service-test fstack-icmp-echo-service.c)
    target_include_directories(ker-fstack-icmp-echo-service-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-fstack-icmp-echo-service-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-fstack-icmp-echo-service-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_arp_responder_port ker_address_headers ker_address_port ker_neighbor_headers ker_neighbor_port
        ker_neighbor_timer_headers ker_neighbor_timer_port ker_neighbor_update_headers ker_neighbor_update_port
        ker_neighbor_event_send_port ker_timer_list_port ker_arp_neighbor_feedback_port ker_arp_probe_port
        ker_arp_port ker_receive_headers ker_receive_port ker_transport_receive_port ker_icmp_echo_service_port
        ker_eth_headers ker_eth_port ker_rx_ring_port ker_tx_export_port ker_tx_ring_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port
        ker_icmp_echo_configured_create_port ker_udp_configured_create_port ker_tcp_configured_create_port
        ker_icmp_echo_create_port ker_udp_create_port ker_tcp_create_port ker_skb_port ker_linux_port
        ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME fstack-icmp-echo-service COMMAND ker-fstack-icmp-echo-service-test)
    set_tests_properties(fstack-icmp-echo-service PROPERTIES TIMEOUT 30)

    add_executable(ker-icmpv4-service-test icmpv4-service.c)
    target_include_directories(ker-icmpv4-service-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-icmpv4-service-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-icmpv4-service-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_arp_responder_port ker_address_headers ker_address_port ker_neighbor_headers ker_neighbor_port
        ker_neighbor_timer_headers ker_neighbor_timer_port ker_neighbor_update_headers ker_neighbor_update_port
        ker_neighbor_event_send_port ker_timer_list_port ker_arp_neighbor_feedback_port ker_arp_probe_port
        ker_arp_port ker_receive_headers ker_receive_port ker_transport_receive_port ker_icmpv4_service_port ker_udp_endpoint_port
        ker_icmpv4_create_port ker_eth_headers ker_eth_port ker_rx_ring_port ker_tx_export_port ker_tx_ring_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port
        ker_udp_configured_create_port ker_tcp_configured_create_port ker_udp_create_port ker_tcp_create_port
        ker_icmp_echo_create_port ker_icmp_echo_configured_create_port ker_skb_port ker_linux_port
        ker_dpdk_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME icmpv4-service COMMAND ker-icmpv4-service-test)
    set_tests_properties(icmpv4-service PROPERTIES TIMEOUT 30)
    add_executable(ker-arp-concurrent-ring-test arp-concurrent-ring.c)
    target_include_directories(ker-arp-concurrent-ring-test PRIVATE "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-arp-concurrent-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-arp-concurrent-ring-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_neighbor_headers ker_neighbor_port ker_address_port ker_arp_port ker_receive_port ker_napi_port ker_eth_port
        ker_rx_ring_port ker_tx_export_port ker_tx_ring_port ker_linux_port ker_dpdk_port ker_skb_port
        Threads::Threads)
    add_test(NAME arp-concurrent-ring COMMAND ker-arp-concurrent-ring-test)
    set_tests_properties(arp-concurrent-ring PROPERTIES TIMEOUT 30)
    add_executable(ker-configured-ring-test configured-ring.c)
    target_include_directories(ker-configured-ring-test PRIVATE "${PROJECT_SOURCE_DIR}/src"
        "${KER_ADDR_IMPORT}" "${KER_NEIGH_UPDATE_IMPORT}")
    target_compile_definitions(ker-configured-ring-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-configured-ring-test PRIVATE ker_arp_rx_headers ker_arp_rx_port
        ker_address_headers ker_address_port ker_arp_port ker_receive_headers ker_receive_port
        ker_eth_headers ker_neighbor_headers ker_neighbor_port ker_timer_list_port
        ker_eth_port ker_rx_ring_port ker_tx_export_port ker_tx_ring_port
        ker_udp_configured_create_port ker_tcp_configured_create_port ker_icmp_echo_configured_create_port
        ker_udp_create_port ker_tcp_create_port ker_icmp_echo_create_port ker_transport_receive_port
        ker_ipv4_view_port ker_udp_view_port ker_tcp_view_port ker_icmpv4_view_port ker_icmp_echo_view_port
        ker_linux_port ker_dpdk_port ker_skb_port PkgConfig::DPDK Threads::Threads)
    add_test(NAME configured-ring COMMAND ker-configured-ring-test)
    set_tests_properties(configured-ring PROPERTIES TIMEOUT 30)
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
    set_tests_properties(icmpv4-service icmpv4-pmtu checksum timer refcount dpdk-memory skb worker flow flow-buckets flow-chain flow-ip-options flow-icmpv4 fstack-flow-receive fstack-flow-owner-receive fstack-flow-concurrent-receive flow-matrix flow-multicore ethernet fstack-ipv4-ingress-validation fstack-udp-ingress-validation fstack-udp-minimal-boundaries fstack-tcp-ingress-validation ipv4-fields transport-receive icmp-echo icmp-echo-configured-create fstack-chain-export fstack-chain-checksum udp-create udp-io udp-flow udp-error udp-configured-create tcp-configured-create udp-ip-options udp-neighbor-create tcp-create tcp-ip-options tcp-neighbor-create tcp-options napi receive arp arp-configured arp-ring arp-responder fstack-icmp-echo-service arp-concurrent-ring configured-ring ipv4-address neighbor-timer neighbor arp-receive fstack-arp-chain-feedback skb-queue timer-list arp-probe-import neighbor-update-import tx-export tx-export-chain tx-ring rx-ring flow-ring cross-worker-ring fstack-concurrent-ring ${ker_fstack_tests} PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
endif()

if(KER_WITH_DPDK AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ker-udp-host-test udp-host.c)
    target_include_directories(ker-udp-host-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-udp-host-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-udp-host-test PRIVATE ker_arp_headers
        ker_neighbor_timer_headers ker_receive_headers ker_udp_io_port ker_udp_error_port
        ker_udp_endpoint_port ker_icmpv4_service_port ker_transport_receive_port ker_udp_view_port
        ker_icmpv4_create_port ker_icmpv4_view_port ker_icmpv4_pmtu_port
        ker_icmp_echo_view_port ker_tcp_view_port ker_ipv4_view_port
        ker_receive_port ker_neighbor_timer_port ker_neighbor_update_port
        ker_neighbor_event_send_port ker_timer_list_port ker_neighbor_port
        ker_address_port ker_arp_port ker_arp_probe_port ker_udp_create_port
        ker_tx_export_port ker_tx_ring_port ker_rx_ring_port
        ker_eth_port ker_skb_port ker_linux_port ker_dpdk_port PkgConfig::DPDK
        Threads::Threads)
    target_link_libraries(ker-udp-host-test PRIVATE ker_arp_rx_headers ker_arp_responder_port ker_arp_rx_port)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(NAME udp-host COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/udp-host.py $<TARGET_FILE:ker-udp-host-test>)
    set_tests_properties(udp-host PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
endif()

if(KER_WITH_DPDK)
    add_executable(ker-tcp-control-test tcp-control.c)
    target_include_directories(ker-tcp-control-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-control-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-control-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    target_link_libraries(ker-tcp-control-test PRIVATE ker_tcp_mss_port)
    add_test(NAME tcp-control COMMAND ker-tcp-control-test)
    set_tests_properties(tcp-control PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
    add_test(NAME tcp-mss-import COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tcp-mss-import.py" "${KER_LINUX_DIR}"
        "${KER_TCP_MSS_MANIFEST}" "${KER_TCP_MSS_IMPORT}"
        "${PROJECT_SOURCE_DIR}/tools/import-linux-tcp-mss.py")
endif()

if(KER_WITH_DPDK)
    add_executable(ker-tcp-listener-test tcp-listener.c)
    target_include_directories(ker-tcp-listener-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-listener-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-listener-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    target_link_libraries(ker-tcp-listener-test PRIVATE ker_tcp_mss_port)
    target_link_libraries(ker-tcp-listener-test PRIVATE ker_tcp_listener_port
        ker_tcp_neighbor_create_port ker_tcp_configured_create_port
        ker_arp_headers ker_arp_rx_headers ker_arp_port ker_arp_responder_port ker_arp_rx_port ker_tx_ring_port)
    add_test(NAME tcp-listener COMMAND ker-tcp-listener-test)
    add_test(NAME tcp-host COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tcp-host.py $<TARGET_FILE:ker-tcp-listener-test>)
    add_test(NAME tcp-passive-persist-host COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tcp-host.py $<TARGET_FILE:ker-tcp-listener-test> persist)
    add_test(NAME tcp-passive-rto-host COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tcp-host.py $<TARGET_FILE:ker-tcp-listener-test> rto)
    add_test(NAME tcp-passive-syn-errors COMMAND ker-tcp-listener-test syn-errors)
    set_tests_properties(tcp-listener tcp-host PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
    set_tests_properties(tcp-passive-syn-errors PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
    set_tests_properties(tcp-host PROPERTIES SKIP_RETURN_CODE 77)
    set_tests_properties(tcp-passive-persist-host PROPERTIES TIMEOUT 45 SKIP_RETURN_CODE 77
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
    set_tests_properties(tcp-passive-rto-host PROPERTIES TIMEOUT 45 SKIP_RETURN_CODE 77
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
endif()

if(KER_WITH_DPDK)
    add_executable(ker-tcp-active-test tcp-active.c)
    target_include_directories(ker-tcp-active-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-active-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-active-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    target_link_libraries(ker-tcp-active-test PRIVATE ker_tcp_mss_port)
    target_link_libraries(ker-tcp-active-test PRIVATE ker_tcp_active_port ker_tcp_listener_port
        ker_tcp_neighbor_create_port ker_tcp_configured_create_port
        ker_arp_headers ker_arp_rx_headers ker_arp_port ker_arp_responder_port ker_arp_rx_port ker_tx_ring_port)
    add_test(NAME tcp-active COMMAND ker-tcp-active-test)
    add_test(NAME tcp-active-host COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tcp-active-host.py $<TARGET_FILE:ker-tcp-active-test>)
    set_tests_properties(tcp-active tcp-active-host PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
    set_tests_properties(tcp-active-host PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(KER_WITH_DPDK)
    add_executable(ker-tcp-stream-test tcp-stream.c)
    target_include_directories(ker-tcp-stream-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-stream-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-stream-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    target_link_libraries(ker-tcp-stream-test PRIVATE ker_tcp_mss_port)
    target_link_libraries(ker-tcp-stream-test PRIVATE ker_tcp_active_port ker_tcp_listener_port
        ker_tcp_neighbor_create_port ker_tcp_configured_create_port
        ker_arp_headers ker_arp_rx_headers ker_arp_port ker_arp_responder_port ker_arp_rx_port ker_tx_ring_port)
    add_test(NAME tcp-stream COMMAND ker-tcp-stream-test)
    add_test(NAME tcp-stream-host COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tcp-stream-host.py $<TARGET_FILE:ker-tcp-stream-test>)
    set_tests_properties(tcp-stream tcp-stream-host PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
    set_tests_properties(tcp-stream-host PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(KER_WITH_DPDK)
    add_executable(ker-tcp-send-test tcp-send.c)
    target_include_directories(ker-tcp-send-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-send-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-send-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    target_link_libraries(ker-tcp-send-test PRIVATE ker_tcp_mss_port)
    target_link_libraries(ker-tcp-send-test PRIVATE ker_tcp_active_port ker_tcp_listener_port
        ker_tcp_neighbor_create_port ker_tcp_configured_create_port
        ker_arp_headers ker_arp_rx_headers ker_arp_port ker_arp_responder_port ker_arp_rx_port ker_tx_ring_port)
    add_test(NAME tcp-send COMMAND ker-tcp-send-test)
    add_test(NAME tcp-send-host COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tcp-send-host.py $<TARGET_FILE:ker-tcp-send-test>)
    add_test(NAME tcp-send-rto-host COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tcp-send-host.py $<TARGET_FILE:ker-tcp-send-test> rto)
    set_tests_properties(tcp-send tcp-send-host tcp-send-rto-host PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
    set_tests_properties(tcp-send-host tcp-send-rto-host PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(KER_WITH_DPDK)
    add_executable(ker-tcp-persist-test tcp-persist.c)
    target_include_directories(ker-tcp-persist-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-persist-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-persist-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    target_link_libraries(ker-tcp-persist-test PRIVATE ker_tcp_mss_port ker_tcp_active_port ker_tcp_listener_port
        ker_tcp_neighbor_create_port ker_tcp_configured_create_port
        ker_arp_headers ker_arp_rx_headers ker_arp_port ker_arp_responder_port ker_arp_rx_port ker_tx_ring_port)
    add_test(NAME tcp-persist COMMAND ker-tcp-persist-test)
    add_test(NAME tcp-persist-host COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tcp-active-persist-host.py $<TARGET_FILE:ker-tcp-persist-test>)
    set_tests_properties(tcp-persist tcp-persist-host PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
    set_tests_properties(tcp-persist-host PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(KER_WITH_DPDK)
    add_executable(ker-tcp-close-test tcp-close.c)
    target_include_directories(ker-tcp-close-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-close-test PRIVATE _GNU_SOURCE)
    target_link_libraries(ker-tcp-close-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    target_link_libraries(ker-tcp-close-test PRIVATE ker_tcp_mss_port)
    target_link_libraries(ker-tcp-close-test PRIVATE ker_tcp_active_port ker_tcp_listener_port
        ker_tcp_neighbor_create_port ker_tcp_configured_create_port
        ker_arp_headers ker_arp_rx_headers ker_arp_port ker_arp_responder_port ker_arp_rx_port ker_tx_ring_port)
    add_test(NAME tcp-close COMMAND ker-tcp-close-test)
    add_test(NAME tcp-close-host COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tcp-close-host.py $<TARGET_FILE:ker-tcp-close-test>)
    set_tests_properties(tcp-close tcp-close-host PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
    set_tests_properties(tcp-close-host PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(KER_WITH_DPDK)
    add_executable(ker-tcp-active-reorder-test tcp-active.c)
    target_include_directories(ker-tcp-active-reorder-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
    target_compile_definitions(ker-tcp-active-reorder-test PRIVATE _GNU_SOURCE KER_TCP_REORDER_TEST)
    target_link_libraries(ker-tcp-active-reorder-test PRIVATE ker_skb_headers ker_eth_headers ker_neighbor_headers ker_timer_list_port ker_linux_port ker_dpdk_port ker_address_port ker_neighbor_port ker_skb_port ker_tx_export_port ker_tcp_create_port ker_tcp_view_port ker_udp_view_port ker_ipv4_view_port ker_icmpv4_view_port ker_icmp_echo_view_port ker_transport_receive_port ker_receive_port ker_receive_headers ker_eth_port Threads::Threads)
    target_link_libraries(ker-tcp-active-reorder-test PRIVATE ker_tcp_mss_port ker_tcp_active_port ker_tcp_listener_port
        ker_tcp_neighbor_create_port ker_tcp_configured_create_port
        ker_arp_headers ker_arp_rx_headers ker_arp_port ker_arp_responder_port ker_arp_rx_port ker_tx_ring_port)
    add_test(NAME tcp-active-reorder COMMAND ker-tcp-active-reorder-test)
    add_test(NAME tcp-active-reorder-host COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tcp-active-reorder-host.py $<TARGET_FILE:ker-tcp-active-reorder-test>)
    set_tests_properties(tcp-active-reorder tcp-active-reorder-host PROPERTIES TIMEOUT 30
        ENVIRONMENT "LD_LIBRARY_PATH=${ker_dpdk_library_path}:$ENV{LD_LIBRARY_PATH}")
    set_tests_properties(tcp-active-reorder-host PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(KER_WITH_DPDK)
    foreach(tcp_test ker-tcp-listener-test ker-tcp-active-test ker-tcp-stream-test ker-tcp-send-test
            ker-tcp-persist-test ker-tcp-close-test ker-tcp-active-reorder-test)
        target_link_libraries(${tcp_test} PRIVATE ker_icmpv4_service_port
            ker_icmpv4_create_port ker_neighbor_timer_port ker_neighbor_timer_headers
            ker_address_headers ker_neighbor_update_headers ker_neighbor_update_port
            ker_neighbor_event_send_headers ker_neighbor_event_send_port ker_arp_probe_port)
    endforeach()
endif()
