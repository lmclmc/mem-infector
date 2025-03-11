cmake_minimum_required(VERSION 3.2)

aux_source_directory(./ BIN_OPT_FILES)

add_executable(bin_opt ${BIN_OPT_FILES})

target_link_libraries(bin_opt infector)
target_link_libraries(bin_opt target)
target_link_libraries(bin_opt xed)

install(FILES ${PROJECT_BINARY_DIR}/demo/bin_opt PERMISSIONS OWNER_EXECUTE 
              OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE WORLD_READ 
              WORLD_WRITE DESTINATION ${PROJECT_BINARY_DIR}/install/demo/)