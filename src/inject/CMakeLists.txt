cmake_minimum_required(VERSION 3.2)

aux_source_directory(./ INJECT_FILES)

add_library(inject SHARED ${INJECT_FILES})