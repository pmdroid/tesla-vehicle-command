#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>

#include <shared.h>

TEST_CASE("BLE advertisement name matches Tesla protocol.md example") {
    unsigned char vin[] = "5YJS0000000000000";
    char identifier[19];
    REQUIRE(TeslaBLE::Common::calculateIdentifier(vin, identifier) == 0);
    REQUIRE(std::string(identifier) == "S1a87a5a75f3df858C");
}

TEST_CASE("BLE length prefix is two-byte big-endian") {
    unsigned char payload[3] = {0xAA, 0xBB, 0xCC};
    unsigned char framed[5];
    size_t framed_size = 0;
    TeslaBLE::Common::PrependLength(payload, sizeof(payload), framed, &framed_size);
    REQUIRE(framed_size == 5);
    REQUIRE(framed[0] == 0);
    REQUIRE(framed[1] == 3);
    REQUIRE(framed[2] == 0xAA);
    REQUIRE(framed[3] == 0xBB);
    REQUIRE(framed[4] == 0xCC);
    REQUIRE(TeslaBLE::Common::ExtractLength(framed) == 3);
}
