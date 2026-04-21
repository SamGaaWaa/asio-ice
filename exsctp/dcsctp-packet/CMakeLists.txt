cmake_minimum_required(VERSION 3.22)

project(dcsctp-packet)

set(CMAKE_CXX_STANDARD 23)

file(GLOB_RECURSE DCSCTP_PACKET_SRC_FILES 
    "common/*.cc"
    "packet/*.cc"
)
add_library(dcsctp_packet STATIC ${DCSCTP_PACKET_SRC_FILES})
target_include_directories(dcsctp_packet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})