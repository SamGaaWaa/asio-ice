cmake_minimum_required(VERSION 3.22)
set(CMAKE_CXX_STANDARD 23)

project(cppmdns)

# set(Boost_DIR "E:\\openSource\\boost_1_88_0\\lib64-msvc-14.3\\cmake\\Boost-1.88.0")
# set(STANDALONE_ASIO_DIR "E:\\openSource\\asio-1_20_0")
# set(STDEXEC_DIR "E:\\openSource\\stdexec")
option(CPPMDNS_USE_BOOST_ASIO "cppmdns uses boost.asio" ON)

file(GLOB SRC_FILES "src/*.cpp")
add_library(cppmdns STATIC ${SRC_FILES})

find_package(Boost 1.89 CONFIG REQUIRED)
if(Boost_FOUND)
    message(STATUS "cppmdns Boost found")
    target_link_libraries(cppmdns PRIVATE Boost::boost)
endif()

if(NOT CPPMDNS_USE_BOOST_ASIO)
    message(STATUS "cppmdns Use standalone Asio")
    set(__CPPMDNS_USE_BOOST_ASIO 0)
    set(ASIO_STANDALONE ON)
    find_package(asio CONFIG REQUIRED)
else()
    message(STATUS "Use Boost Asio")
    set(__CPPMDNS_USE_BOOST_ASIO 1)
    target_link_libraries(cppmdns PUBLIC Boost::headers)
endif()
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/include/config.hpp.in" "${CMAKE_CURRENT_SOURCE_DIR}/include/config.hpp")

add_library(cppmdns_compile_flags INTERFACE)
target_compile_options(cppmdns_compile_flags INTERFACE
                       $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-fconcepts-diagnostics-depth=10 -Wno-non-template-friend -Wall -fcoroutines>
                       )
target_compile_options(cppmdns_compile_flags INTERFACE
                       $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/Zc:__cplusplus /Zc:preprocessor /D_WIN32_WINNT=0x0601 /Zm200 /bigobj /W4 /wd4100 /wd4101 /wd4127 /wd4324 /wd4456 /wd4459>
                       )
if(NOT CPPMDNS_USE_BOOST_ASIO)
    target_link_libraries(cppmdns_compile_flags INTERFACE asio::asio)
    target_compile_definitions(cppmdns_compile_flags INTERFACE ASIO_STANDALONE)
endif()

target_link_libraries(cppmdns PRIVATE cppmdns_compile_flags)
target_include_directories(cppmdns PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(cppmdns PUBLIC ${STDEXEC_DIR})
target_include_directories(cppmdns PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/3rd/asio2exec")

add_executable(cppmdns_test main.cpp)
target_link_libraries(cppmdns_test cppmdns cppmdns_compile_flags)
target_include_directories(cppmdns_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/3rd/asio2exec)
