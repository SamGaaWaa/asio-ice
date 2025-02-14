cmake_minimum_required(VERSION 3.22)

project(tiny-boost)

add_library(tiny_boost INTERFACE)
target_include_directories(tiny_boost INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})