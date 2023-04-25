cmake_minimum_required(VERSION 3.2)

aux_source_directory(./ VIRUS_FILES)

add_executable(virus ${VIRUS_FILES})

target_link_libraries(virus infector)
target_link_libraries(virus target)
target_link_libraries(virus xed)

install(FILES ${PROJECT_BINARY_DIR}/demo/virus PERMISSIONS OWNER_EXECUTE 
              OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE WORLD_READ 
              WORLD_WRITE DESTINATION ${PROJECT_BINARY_DIR}/install/demo/)