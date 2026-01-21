add_library(libvsdb process.cpp)
add_library(vsdb::libvsdb ALIAS libvsdb)

set_target_properties(
    libvsdb
    PROPERTIES OUTPUT_NAME vsdb
)

target_compile_features(libvsdb PUBLIC cxx_std_17)

target_include_directories(
    libvsdb
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/include
        ${CMAKE_SOURCE_DIR}/external/raw_pdb/src
)

# target_link_libraries(
#     libvsdb
#     PRIVATE
#         raw_pdb
# )

include(GNUInstallDirs)
install(
    TARGETS libvsdb
    EXPORT vsdb-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    DIRECTORY ${PROJECT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    EXPORT vsdb-targets
    FILE vsdb-config.cmake
    NAMESPACE vsdb::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vsdb
)
