cmake_minimum_required(VERSION 3.19)

project("vsdb" LANGUAGES CXX)

find_package(Threads REQUIRED)
find_package(replxx CONFIG REQUIRED)

include(CTest)

add_subdirectory("external/raw_pdb/src")
add_subdirectory("src")
add_subdirectory("tools")

