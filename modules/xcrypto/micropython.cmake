add_library(usermod_xcrypto INTERFACE)
target_sources(usermod_xcrypto INTERFACE ${CMAKE_CURRENT_LIST_DIR}/xcrypto.c)
target_include_directories(usermod_xcrypto INTERFACE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(usermod INTERFACE usermod_xcrypto)