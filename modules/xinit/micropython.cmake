add_library(usermod_xinit INTERFACE)
target_sources(usermod_xinit INTERFACE ${CMAKE_CURRENT_LIST_DIR}/xinit.c)
target_link_libraries(usermod INTERFACE usermod_xinit)