# Import an explicit header set rather than exposing the entire kernel include
# tree or depending on the host's /usr/include/linux headers.
set(KER_LINUX_DIR "${PROJECT_SOURCE_DIR}/third_party/linux")
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The initial userspace Linux port currently supports Linux hosts only")
endif()
set(KER_LINUX_INCLUDE "${PROJECT_BINARY_DIR}/linux-include")
set(KER_LINUX_HEADERS
    asm-generic/checksum.h
    linux/container_of.h
    linux/rbtree.h
    linux/rbtree_augmented.h
    linux/rbtree_types.h
    linux/timerqueue.h
    linux/timerqueue_types.h
    net/checksum.h)
set(KER_LINUX_SOURCES
    "${KER_LINUX_DIR}/lib/checksum.c"
    "${KER_LINUX_DIR}/lib/rbtree.c"
    "${KER_LINUX_DIR}/lib/timerqueue.c")

foreach(source IN LISTS KER_LINUX_SOURCES)
    if(NOT EXISTS "${source}")
        message(FATAL_ERROR "Missing ${source}. Run git submodule update --init --recursive --depth 1")
    endif()
endforeach()
foreach(header IN LISTS KER_LINUX_HEADERS)
    configure_file("${KER_LINUX_DIR}/include/${header}"
        "${KER_LINUX_INCLUDE}/${header}" COPYONLY)
endforeach()
foreach(header asm-generic/errno.h asm-generic/errno-base.h)
    configure_file("${KER_LINUX_DIR}/include/uapi/${header}"
        "${KER_LINUX_INCLUDE}/${header}" COPYONLY)
endforeach()
# Reject newly introduced kernel includes before the compiler could silently
# pick up a similarly named host UAPI header. This is deliberately conservative
# and includes dependencies inside conditional preprocessor branches.
set(KER_LINUX_ALLOWED_HEADERS ${KER_LINUX_HEADERS} asm-generic/errno.h asm-generic/errno-base.h)
file(GLOB_RECURSE KER_COMPAT_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/src/compat/include/*.h")
set(KER_LINUX_AUDIT_FILES ${KER_LINUX_SOURCES} ${KER_COMPAT_HEADERS})
foreach(header IN LISTS KER_LINUX_ALLOWED_HEADERS)
    list(APPEND KER_LINUX_AUDIT_FILES "${KER_LINUX_INCLUDE}/${header}")
endforeach()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${KER_LINUX_SOURCES})
foreach(source IN LISTS KER_LINUX_AUDIT_FILES)
    file(STRINGS "${source}" includes REGEX "^[ \t]*#[ \t]*include")
    foreach(line IN LISTS includes)
        if(line MATCHES "<((linux|net|asm|asm-generic|uapi|trace)/[^>]+)>")
            set(header "${CMAKE_MATCH_1}")
            if(NOT header IN_LIST KER_LINUX_ALLOWED_HEADERS AND
               NOT EXISTS "${PROJECT_SOURCE_DIR}/src/compat/include/${header}")
                message(FATAL_ERROR "Unsupported kernel header ${header} included by ${source}")
            endif()
        endif()
    endforeach()
endforeach()
if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    message(FATAL_ERROR "The Linux port requires a compiler supporting GNU C extensions")
endif()

add_library(ker_port_headers INTERFACE)
target_compile_definitions(ker_port_headers INTERFACE _POSIX_C_SOURCE=200809L)
target_include_directories(ker_port_headers INTERFACE
    "${PROJECT_SOURCE_DIR}/src/compat/include"
    "${PROJECT_SOURCE_DIR}/src")
target_include_directories(ker_port_headers SYSTEM INTERFACE "${KER_LINUX_INCLUDE}")
target_compile_options(ker_port_headers INTERFACE
    -include "${PROJECT_SOURCE_DIR}/src/compat/namespace.h"
    -fno-strict-aliasing)

add_library(ker_linux_port OBJECT ${KER_LINUX_SOURCES} src/runtime/timer.c)
# Upstream uses empty callbacks with intentionally unused parameters.
set_source_files_properties(${KER_LINUX_SOURCES} PROPERTIES COMPILE_OPTIONS -Wno-unused-parameter)
target_link_libraries(ker_linux_port PRIVATE ker_port_headers)
target_compile_features(ker_linux_port PRIVATE c_std_11)
set_target_properties(ker_linux_port PROPERTIES
    POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden C_EXTENSIONS ON)
