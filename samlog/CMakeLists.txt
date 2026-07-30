cmake_minimum_required(VERSION 3.22)

project(samlog)
set(CMAKE_CXX_STANDARD 23)

add_library(samlog src/samlog.cpp)
target_include_directories(samlog PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)