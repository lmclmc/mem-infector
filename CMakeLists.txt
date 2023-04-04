cmake_minimum_required(VERSION 3.2)

project(infector)

include_directories(src/)
include_directories(${CMAKE_INCLUDE_PATH})

link_directories(${CMAKE_LIBRARY_PATH})

add_subdirectory(src/)