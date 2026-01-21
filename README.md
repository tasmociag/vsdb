# vsdb
Victor's Simple Debugger

## Requirements
https://github.com/microsoft/vcpkg.git

## Instalation
mkdir build && cd build

cmake .. -DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake

cmake --build .

## Usage example
.\build\tools\Debug\vsdb.exe -e .\build\tools\Debug\outputDebugString.exe
