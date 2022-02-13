cmake_minimum_required(VERSION 3.2)

aux_source_directory(./ XED_FILES)

add_library(xed ${XED_FILES})

