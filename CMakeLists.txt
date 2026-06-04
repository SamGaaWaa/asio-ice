cmake_minimum_required(VERSION 3.22)

project(asio-ice)

option(ASIOICE_TEST "Build test" ON)
option(ASIOICE_USE_OPENSSL "Use OpenSSL" OFF)
option(ASIOICE_ENABLE_DTLS "Enable DTLS" OFF)
option(ASIOICE_ENABLE_SCTP_OVER_DTLS "Enable SCTP over DTLS" OFF)

if(ASIOICE_ENABLE_SCTP_OVER_DTLS)
    set(ASIOICE_ENABLE_DTLS ON)
    set(ASIOICE_USE_OPENSSL ON)
endif()

if(ASIOICE_ENABLE_DTLS)
    set(ASIOICE_USE_OPENSSL ON)
endif()

set(CMAKE_CXX_STANDARD 23)
set(STANDALONE_ASIO_DIR "E:\\openSource\\asio")
# set(STDEXEC_DIR "E:\\openSource\\asio2exec\\stdexec")
# set(Boost_DIR "D:\\openSource\\boost_1_88_0_prebuild\\lib64-msvc-14.3\\cmake\\Boost-1.88.0")
set(ASIOICE_USE_BOOST_ASIO ON)
# set(OPENSSL_DIR "E:\\openSource\\openssl-3.1.0\\x64")
# set(OPENSSL_LIB_DIR ${OPENSSL_DIR}/lib)
# set(OPENSSL_INCLUDE_DIR ${OPENSSL_DIR}/include)
# set(OPENSSL_ROOT_DIR "E:\\openSource\\openssl-3.1.0\\x64" CACHE PATH "OpenSSL root directory")
set(ENABLE_IO_URING OFF)

if(ASIOICE_USE_OPENSSL)
    find_package(OpenSSL 3 REQUIRED)
endif()

if(ASIOICE_USE_BOOST_ASIO)
    set(__ASIOICE_USE_BOOST_ASIO 1)
    # set(CPPMDNS_USE_BOOST_ASIO ON)
else()
    set(__ASIOICE_USE_BOOST_ASIO 0)
    # set(CPPMDNS_USE_BOOST_ASIO OFF)
endif()

set(Boost_DEBUG ON)
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.89 CONFIG REQUIRED)
if(Boost_FOUND)
    message(STATUS "Boost found")
endif()

if(ENABLE_IO_URING)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(ASIOICE_ENABLE_IO_URING 1)
        message(STATUS "liburing support enabled")
    else()
        set(ASIOICE_ENABLE_IO_URING 0)
        message(WARNING "ENABLE_IO_URING is ON, but system is not Linux. Disabling.")
    endif()
else()
    set(ASIOICE_ENABLE_IO_URING 0)
endif()
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/include/asioice/config.hpp.in" "${CMAKE_CURRENT_SOURCE_DIR}/include/asioice/config.hpp")

# add_subdirectory(cppmdns)
if(ASIOICE_ENABLE_SCTP_OVER_DTLS)
    add_subdirectory(exsctp)
endif()

file(GLOB ICE_SRC_FILES 
    src/stun.cpp
    src/base64.cpp
    src/address.cpp
    src/candidate.cpp
    src/hash.cpp
    src/candidate_pair.cpp
    src/string_utils.cpp
    src/io_buffer.cpp
    src/agent_base.cpp
    src/agent_base_impl.cpp
    src/agent.cpp
)
if(ASIOICE_ENABLE_DTLS)
    list(APPEND ICE_SRC_FILES src/ssl/datagram_bio.cpp src/ssl/dtls_certificate.cpp)
endif()
add_library(asioice STATIC ${ICE_SRC_FILES})

if(ASIOICE_ENABLE_IO_URING)
    target_link_libraries(asioice PUBLIC uring)
endif()

add_library(asioice_compile_flags INTERFACE)
target_compile_options(asioice_compile_flags INTERFACE
                       $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-fconcepts-diagnostics-depth=10 -Wno-non-template-friend -Wall -fcoroutines>
                       )
target_compile_options(asioice_compile_flags INTERFACE
                       $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/Zc:__cplusplus /Zc:preprocessor /utf-8 /D_WIN32_WINNT=0x0601 /Zm200 /bigobj /W4 /wd4100 /wd4101 /wd4127 /wd4324 /wd4456 /wd4459>
                       )
target_link_libraries(asioice_compile_flags INTERFACE
                      $<$<PLATFORM_ID:Windows>:bcrypt;ws2_32;iphlpapi;mswsock>
                      )
target_compile_options(asioice_compile_flags INTERFACE
                       $<$<AND:$<COMPILE_LANG_AND_ID:CXX,GNU>,$<PLATFORM_ID:Windows>>:-Wa,-mbig-obj>
                       )
target_link_libraries(asioice PRIVATE Boost::boost asioice_compile_flags)
if(ASIOICE_USE_OPENSSL)
    target_link_libraries(asioice PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
if(ASIOICE_ENABLE_SCTP_OVER_DTLS)
    target_link_libraries(asioice PUBLIC exsctp)
endif()

if(NOT ASIOICE_USE_BOOST_ASIO)
    target_include_directories(asioice PUBLIC ${STANDALONE_ASIO_DIR}/asio/include)
endif()
target_include_directories(asioice PUBLIC ${STDEXEC_DIR})
target_include_directories(asioice PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(asioice PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(asioice PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

add_library(asioice_test_flags INTERFACE)
target_link_libraries(asioice_test_flags INTERFACE Boost::boost)
if(NOT ASIOICE_USE_BOOST_ASIO)
    target_include_directories(asioice_test_flags INTERFACE ${STANDALONE_ASIO_DIR}/asio/include)
endif()
target_link_libraries(asioice_test_flags INTERFACE asioice asioice_compile_flags)
target_include_directories(asioice_test_flags INTERFACE ${STDEXEC_DIR})
target_include_directories(asioice_test_flags INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(asioice_test_flags INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(asioice_test_flags INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

if(ASIOICE_TEST)
    file(GLOB TEST_SOURCES
        src/boost_fiber_test.cpp
        src/io_buffer_test.cpp
        src/on_scope_empty_test.cpp
        src/hash_test.cpp
        src/stun_client_test.cpp
        src/stun_test.cpp
        src/async_queue_test.cpp
        src/candidate_test.cpp
        src/turn_client_test.cpp
    )
    if(ASIOICE_ENABLE_DTLS)
        list(APPEND TEST_SOURCES src/dtls_test.cpp)
    endif()
    if(ASIOICE_ENABLE_SCTP_OVER_DTLS)
        list(APPEND TEST_SOURCES src/ice_test.cpp)
        list(APPEND TEST_SOURCES src/sctp_test.cpp)
    endif()
    foreach(TEST_FILE ${TEST_SOURCES})
        get_filename_component(EXECUTABLE_NAME ${TEST_FILE} NAME_WE)
        add_executable(${EXECUTABLE_NAME} ${TEST_FILE})
        target_link_libraries(${EXECUTABLE_NAME} PRIVATE asioice_test_flags)
    endforeach()
    if(ASIOICE_ENABLE_DTLS)
        target_link_libraries(dtls_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(ASIOICE_ENABLE_SCTP_OVER_DTLS)
        target_link_libraries(ice_test PRIVATE OpenSSL::SSL OpenSSL::Crypto exsctp)
        target_link_libraries(sctp_test PRIVATE OpenSSL::SSL OpenSSL::Crypto exsctp)
    endif()
endif()

if(ASIOICE_ENABLE_SCTP_OVER_DTLS)
    add_subdirectory(example/aiortc)
    add_subdirectory(example/pion)
    add_subdirectory(example/werift)
endif()