cmake_minimum_required(VERSION 3.2)

project(infector)

set(KDIR /home/lmc/Desktop/linux-5.4.90)

include_directories(src/)
include_directories(${CMAKE_INCLUDE_PATH})

add_subdirectory(src/)