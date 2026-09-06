#include <catch2/catch_test_macros.hpp>

#include <mbedtls/version.h>
#include <pb.h>

TEST_CASE("host mbedtls is 3.6 LTS at patch 7 or newer") {
    REQUIRE(MBEDTLS_VERSION_MAJOR == 3);
    REQUIRE(MBEDTLS_VERSION_MINOR == 6);
    REQUIRE(MBEDTLS_VERSION_PATCH >= 7);
}

TEST_CASE("nanopb pb.h matches generated proto header version") {
    REQUIRE(PB_PROTO_HEADER_VERSION == 40);
}
