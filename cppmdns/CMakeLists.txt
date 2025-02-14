cmake_minimum_required(VERSION 3.22)
set(CMAKE_CXX_STANDARD 23)

project(cppmdns)

if(USE_BOOST)
    set(CPPMDNS_USE_BOOST 1)
else()
    set(CPPMDNS_USE_BOOST 0)
    message(STATUS "Use standalone Asio, ${STANDALONE_ASIO_DIR}")
endif()
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/include/config.hpp.in" "${CMAKE_CURRENT_SOURCE_DIR}/include/config.hpp")

file(GLOB SRC_FILES "src/*.cpp")
add_library(cppmdns STATIC ${SRC_FILES})
if(NOT USE_BOOST)
    message(STATUS "Use standalone Asio")
    add_library(boost_intrusive INTERFACE)
    target_include_directories(boost_intrusive INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/3rd")
    target_link_libraries(cppmdns PRIVATE boost_intrusive)
    target_include_directories(cppmdns PUBLIC ${STANDALONE_ASIO_DIR}/asio/include)
else()
    message(STATUS "Use Boost.Asio")
    find_package(Boost CONFIG REQUIRED PATHS ${BOOST_DIR})
    if(Boost_FOUND)
        message(STATUS "Boost found")
        target_link_libraries(cppmdns PUBLIC Boost::boost)
    endif()
endif()

add_library(compile_flags INTERFACE)
target_compile_options(compile_flags INTERFACE
                       $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-fconcepts-diagnostics-depth=10 -Wno-non-template-friend -Wall -fcoroutines>
                       )
target_compile_options(compile_flags INTERFACE
                       $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/Zc:__cplusplus /Zc:preprocessor /D_WIN32_WINNT=0x0601 /Zm200 /bigobj /W4 /wd4100 /wd4101 /wd4127 /wd4324 /wd4456 /wd4459>
                       )

target_link_libraries(cppmdns PUBLIC compile_flags)
target_include_directories(cppmdns PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(cppmdns PUBLIC ${STDEXEC_DIR}/include)
target_include_directories(cppmdns PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/3rd/asio2exec")

add_executable(cppmdns_test main.cpp)
target_link_libraries(cppmdns_test cppmdns)
target_include_directories(cppmdns_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/3rd/asio2exec)
