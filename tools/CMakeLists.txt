add_executable(vsdb vsdb.cpp)
target_link_libraries(vsdb PRIVATE vsdb::libvsdb replxx::replxx raw_pdb)

include(GNUInstallDirs)
install(
    TARGETS vsdb
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if (MSVC)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT
        "$<$<CONFIG:Debug>:ProgramDatabase>"
        "$<$<CONFIG:RelWithDebInfo>:ProgramDatabase>"
    )
endif()

add_executable(outputDebugString outputDebugString.cpp)
