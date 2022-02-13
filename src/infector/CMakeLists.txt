cmake_minimum_required(VERSION 3.2)

aux_source_directory(./ INFECTOR_FILES)

add_library(infector STATIC ${INFECTOR_FILES})