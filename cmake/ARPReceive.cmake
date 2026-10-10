set(KER_ARP_RX_IMPORT "${PROJECT_BINARY_DIR}/linux-arp-receive")
set(KER_ARP_RX_MANIFEST "${PROJECT_SOURCE_DIR}/src/compat/linux-arp-receive-manifest.json")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/import-linux-arp-receive.py"
    --linux "${KER_LINUX_DIR}" --manifest "${KER_ARP_RX_MANIFEST}" --out "${KER_ARP_RX_IMPORT}"
    RESULT_VARIABLE ker_arp_rx_result ERROR_VARIABLE ker_arp_rx_error)
if(NOT ker_arp_rx_result EQUAL 0)
    message(FATAL_ERROR "Linux ARP receive import failed: ${ker_arp_rx_error}")
endif()
file(READ "${KER_ARP_RX_MANIFEST}" ker_arp_rx_manifest_json)
string(JSON ker_arp_rx_files LENGTH "${ker_arp_rx_manifest_json}" files)
math(EXPR ker_arp_rx_last "${ker_arp_rx_files} - 1")
foreach(ker_arp_rx_index RANGE ${ker_arp_rx_last})
    string(JSON ker_arp_rx_file MEMBER "${ker_arp_rx_manifest_json}" files ${ker_arp_rx_index})
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${KER_LINUX_DIR}/${ker_arp_rx_file}")
endforeach()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${KER_ARP_RX_MANIFEST}"
    "${PROJECT_SOURCE_DIR}/tools/import-linux-arp-receive.py" "${PROJECT_SOURCE_DIR}/tools/import-linux-skb.py")
add_library(ker_arp_rx_headers INTERFACE)
target_include_directories(ker_arp_rx_headers SYSTEM INTERFACE "${KER_ARP_RX_IMPORT}")
target_link_libraries(ker_arp_rx_headers INTERFACE ker_arp_headers ker_receive_headers ker_address_headers)
add_library(ker_arp_rx_port OBJECT "${KER_ARP_RX_IMPORT}/linux_arp_receive.c" src/runtime/arp-receive.c)
target_link_libraries(ker_arp_rx_port PRIVATE ker_arp_rx_headers)
target_compile_features(ker_arp_rx_port PRIVATE c_std_11)
set_target_properties(ker_arp_rx_port PROPERTIES POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)

# Raw Linux callbacks retain unused parameters in the disabled profile.
set_source_files_properties("${KER_ARP_RX_IMPORT}/linux_arp_receive.c" PROPERTIES COMPILE_OPTIONS -Wno-unused-parameter)
