add_library(usermod_xpolicy INTERFACE)
target_sources(usermod_xpolicy INTERFACE ${CMAKE_CURRENT_LIST_DIR}/xpolicy.c)
target_include_directories(usermod_xpolicy INTERFACE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(usermod INTERFACE usermod_xpolicy)