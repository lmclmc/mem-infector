cmake_minimum_required(VERSION 3.2)

aux_source_directory(./ LOG_FILES)

add_compile_options(-fPIC)
add_library(log STATIC ${LOG_FILES})