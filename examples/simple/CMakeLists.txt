cmake_minimum_required(VERSION 3.22)
project(simple)

include(FetchContent)
FetchContent_Declare(
        simpleble
        GIT_REPOSITORY https://github.com/OpenBluetoothToolbox/SimpleBLE.git
        GIT_TAG v0.7.3
        GIT_SHALLOW YES
)

set(CMAKE_CXX_STANDARD 17)

FetchContent_GetProperties(simpleble)
if (NOT simpleble_POPULATED)
    FetchContent_Populate(simpleble)
    list(APPEND CMAKE_MODULE_PATH "${simpleble_SOURCE_DIR}/cmake/find")
    add_subdirectory("${simpleble_SOURCE_DIR}/simpleble" "${simpleble_BINARY_DIR}")
endif ()

set(simpleble_FOUND 1)

add_subdirectory(../../ TeslaBLE)
add_executable(bluetooth ble.cpp src/ble.cpp)
target_link_libraries(bluetooth PRIVATE TeslaBLE simpleble::simpleble)
target_include_directories(bluetooth PRIVATE include/)

