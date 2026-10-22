add_library(usermod_xkeys INTERFACE)
target_sources(usermod_xkeys INTERFACE ${CMAKE_CURRENT_LIST_DIR}/xkeys.c)
target_link_libraries(usermod INTERFACE usermod_xkeys)
target_include_directories(usermod_xkeys INTERFACE ${CMAKE_CURRENT_LIST_DIR})