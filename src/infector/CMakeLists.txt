cmake_minimum_required(VERSION 3.2)

FILE(GLOB_RECURSE INFECTOR_FILES ./*.cpp)

add_library(infector STATIC ${INFECTOR_FILES})