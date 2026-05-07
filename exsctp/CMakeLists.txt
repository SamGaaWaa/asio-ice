cmake_minimum_required(VERSION 3.22)

project(exsctp)

option(EXSCTP_TEST "Build test" ON)

set(CMAKE_CXX_STANDARD 23)

set(Boost_DEBUG ON)
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.89 CONFIG REQUIRED COMPONENTS json context)
if(Boost_FOUND)
    message(STATUS "Boost found")
endif()

add_subdirectory(dcsctp)

add_library(exsctp INTERFACE)

add_library(exsctp_compile_flags INTERFACE)
target_compile_options(exsctp_compile_flags INTERFACE
                       $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-fconcepts-diagnostics-depth=10 -Wno-non-template-friend -Wall -fcoroutines>
                       )
target_compile_options(exsctp_compile_flags INTERFACE
                       $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/Zc:__cplusplus /Zc:preprocessor /D_WIN32_WINNT=0x0601 /Zm200 /bigobj /W4 /wd4100 /wd4101 /wd4127 /wd4324 /wd4456 /wd4459>
                       )

target_link_libraries(exsctp INTERFACE dcsctp Boost::boost exsctp_compile_flags)
target_include_directories(exsctp INTERFACE ${STDEXEC_DIR})
target_include_directories(exsctp INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

add_library(test_flags INTERFACE)
target_link_libraries(test_flags INTERFACE Boost::boost)
target_link_libraries(test_flags INTERFACE exsctp exsctp_compile_flags)
target_include_directories(test_flags INTERFACE ${STDEXEC_DIR})
target_include_directories(test_flags INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

file(GLOB TEST_SOURCES "*_test.cpp")
if(EXSCTP_TEST)
    foreach(TEST_FILE ${TEST_SOURCES})
        get_filename_component(EXECUTABLE_NAME ${TEST_FILE} NAME_WE)
        add_executable(${EXECUTABLE_NAME} ${TEST_FILE})
        target_link_libraries(${EXECUTABLE_NAME} PRIVATE test_flags)
    endforeach()
endif()