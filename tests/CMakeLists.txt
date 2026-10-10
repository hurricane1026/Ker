add_executable(ker-checksum-test checksum.c)
target_link_libraries(ker-checksum-test PRIVATE ker::ker ker_port_headers ker_linux_port)
add_test(NAME checksum COMMAND ker-checksum-test)

add_executable(ker-timer-test timer.c)
target_link_libraries(ker-timer-test PRIVATE ker_port_headers ker_linux_port)
add_test(NAME timer COMMAND ker-timer-test)
