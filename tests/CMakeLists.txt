include(FetchContent)
FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.7.1
        GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(Catch2)
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)

add_executable(tesla_ble_tests
        test_metadata.cpp
        test_ble.cpp
        test_commands.cpp
)
target_include_directories(tesla_ble_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tesla_ble_tests PRIVATE TeslaBLE Catch2::Catch2WithMain)

include(Catch)
catch_discover_tests(tesla_ble_tests)
