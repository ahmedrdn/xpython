add_library(usermod_xwatch INTERFACE)
target_sources(usermod_xwatch INTERFACE ${CMAKE_CURRENT_LIST_DIR}/xwatch.c)
target_link_libraries(usermod INTERFACE usermod_xwatch)