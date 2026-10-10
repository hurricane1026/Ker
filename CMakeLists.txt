cmake_minimum_required(VERSION 3.20)
project(ker VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(KER_BUILD_EXAMPLES "Build API examples" ON)

add_library(ker src/ker.c)
add_library(ker::ker ALIAS ker)
target_compile_features(ker PUBLIC c_std_11)
target_include_directories(ker PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_definitions(ker PRIVATE KER_VERSION="${PROJECT_VERSION}")
set_target_properties(ker PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0)

if(KER_BUILD_EXAMPLES)
    add_executable(ker-info examples/info.c)
    target_link_libraries(ker-info PRIVATE ker::ker)
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
