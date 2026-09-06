cmake_minimum_required(VERSION 3.20)
include(FetchContent)
project(TeslaBLE
        VERSION 1.0.0
        DESCRIPTION "CPP Tesla BLE Library"
        LANGUAGES CXX C
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
cmake_policy(SET CMP0077 NEW)
if (POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif ()
set(MBEDTLS_AS_SUBPROJECT ON)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(TESLA_BLE_BUILD_TESTS_DEFAULT ON)
else ()
    set(TESLA_BLE_BUILD_TESTS_DEFAULT OFF)
endif ()
option(TESLA_BLE_BUILD_TESTS "Build host unit tests" ${TESLA_BLE_BUILD_TESTS_DEFAULT})

FetchContent_Declare(
        nanopb
        GIT_REPOSITORY https://github.com/nanopb/nanopb.git
        GIT_TAG 0.4.9.2
        GIT_SHALLOW TRUE
)
FetchContent_Declare(
        mbedtls
        GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
        GIT_TAG v3.6.7
        GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(mbedtls)
FetchContent_GetProperties(nanopb)
if (NOT nanopb_POPULATED)
    FetchContent_Populate(nanopb)
endif ()

# Common source files
set(COMMON_SOURCES
        src/authenticator.cpp
        src/metadata.cpp
        src/session.cpp
        src/shared.cpp
        src/carserver.cpp
        src/security.cpp
        src/ble_frame.cpp
)

# NanoPB source files
set(NANOPB_SOURCES
        ${nanopb_SOURCE_DIR}/pb_decode.c
        ${nanopb_SOURCE_DIR}/pb_encode.c
        ${nanopb_SOURCE_DIR}/pb_common.c
)

# Protobuf source files
set(PROTOBUF_SOURCES
        src/car_server.pb.c
        src/common.pb.c
        src/errors.pb.c
        src/keys.pb.c
        src/managed_charging.pb.c
        src/signatures.pb.c
        src/universal_message.pb.c
        src/vcsec.pb.c
        src/vehicle.pb.c
)

set(ALL_SOURCES ${COMMON_SOURCES} ${NANOPB_SOURCES} ${PROTOBUF_SOURCES})
add_library(TeslaBLE STATIC ${ALL_SOURCES})
target_compile_options(TeslaBLE PRIVATE -Wall -g -O0)

# Include directories
target_include_directories(TeslaBLE
        PRIVATE
        src/
        include/
        PUBLIC
        include/
        include/protobuf/
        ${nanopb_SOURCE_DIR}
        ${NANOPB_INCLUDE_DIRS}
        ${CMAKE_CURRENT_BINARY_DIR}
)

# Link libraries
target_link_libraries(TeslaBLE PUBLIC mbedcrypto)

# Public headers
set(PUBLIC_HEADERS
        include/authenticator.h
        include/metadata.h
        include/shared.h
        include/carserver.h
        include/security.h
        include/ble_frame.h
        include/car_server.pb.h
        include/common.pb.h
        include/errors.pb.h
        include/keys.pb.h
        include/managed_charging.pb.h
        include/signatures.pb.h
        include/universal_message.pb.h
        include/vcsec.pb.h
        include/vehicle.pb.h
)

# Set public headers
foreach (HEADER ${PUBLIC_HEADERS})
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER ${HEADER})
endforeach ()

if (TESLA_BLE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif ()
