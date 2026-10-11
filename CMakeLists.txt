cmake_minimum_required(VERSION 3.20)
project(ker VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(KER_BUILD_EXAMPLES "Build API examples" ON)
include(CTest)
include(cmake/LinuxPort.cmake)
option(KER_WITH_DPDK "Build the DPDK memory and packet adapter" ON)
if(KER_WITH_DPDK)
    include(cmake/DPDK.cmake)
    include(cmake/SKB.cmake)
    include(cmake/Ethernet.cmake)
    include(cmake/NAPI.cmake)
    include(cmake/Receive.cmake)
    include(cmake/ARP.cmake)
    include(cmake/IPv4Address.cmake)
    include(cmake/Neighbor.cmake)
    include(cmake/ARPReceive.cmake)
    include(cmake/TimerList.cmake)
    include(cmake/NeighborTimer.cmake)
endif()

add_library(ker src/ker.c src/checksum.c $<TARGET_OBJECTS:ker_linux_port>)
if(KER_WITH_DPDK)
    target_sources(ker PRIVATE $<TARGET_OBJECTS:ker_dpdk_port>)
    target_sources(ker PRIVATE $<TARGET_OBJECTS:ker_skb_port> $<TARGET_OBJECTS:ker_eth_port> $<TARGET_OBJECTS:ker_napi_port> $<TARGET_OBJECTS:ker_receive_port> $<TARGET_OBJECTS:ker_arp_port> $<TARGET_OBJECTS:ker_address_port> $<TARGET_OBJECTS:ker_neighbor_port> $<TARGET_OBJECTS:ker_arp_rx_port> $<TARGET_OBJECTS:ker_timer_list_port> $<TARGET_OBJECTS:ker_neighbor_timer_port>)
    target_link_libraries(ker PRIVATE PkgConfig::DPDK)
    foreach(ker_dpdk_libdir IN LISTS DPDK_LIBRARY_DIRS)
        target_link_options(ker INTERFACE "$<BUILD_INTERFACE:LINKER:-rpath-link,${ker_dpdk_libdir}>")
    endforeach()
endif()
add_library(ker::ker ALIAS ker)
target_compile_features(ker PUBLIC c_std_11)
target_include_directories(ker PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_definitions(ker PRIVATE KER_VERSION="${PROJECT_VERSION}")
target_link_libraries(ker PRIVATE $<BUILD_INTERFACE:ker_port_headers> Threads::Threads)
set_target_properties(ker PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0
    C_VISIBILITY_PRESET hidden)

if(KER_BUILD_EXAMPLES)
    add_executable(ker-info examples/info.c)
    target_link_libraries(ker-info PRIVATE ker::ker)
    add_executable(ker-checksum examples/checksum.c)
    target_link_libraries(ker-checksum PRIVATE ker::ker)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

install(TARGETS ker EXPORT kerTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ker DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT kerTargets NAMESPACE ker:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ker)
configure_package_config_file(cmake/kerConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/kerConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ker)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/kerConfigVersion.cmake
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/kerConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/kerConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ker)
