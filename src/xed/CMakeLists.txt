cmake_minimum_required(VERSION 3.2)

aux_source_directory(./ XED_FILES)

add_library(xed ${XED_FILES})

install(FILES ${PROJECT_BINARY_DIR}/src/xed/libxed.a DESTINATION 
              ${PROJECT_BINARY_DIR}/install/lib/)