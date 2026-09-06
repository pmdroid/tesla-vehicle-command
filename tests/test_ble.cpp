#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>
#include <cstdlib>

#include <ble_frame.h>
#include <shared.h>

TEST_CASE("BLE advertisement name matches Tesla protocol.md example") {
    unsigned char vin[17];
    memcpy(vin, "5YJS0000000000000", 17);
    char identifier[19];
    REQUIRE(TeslaBLE::Common::calculateIdentifier(vin, identifier) == 0);
    REQUIRE(std::string(identifier) == "S1a87a5a75f3df858C");
}

TEST_CASE("HexStrToUint8 returns null on invalid digits") {
    REQUIRE(TeslaBLE::Common::HexStrToUint8("zz") == nullptr);
    unsigned char *ok = TeslaBLE::Common::HexStrToUint8("0a");
    REQUIRE(ok != nullptr);
    REQUIRE(ok[0] == 0x0a);
    free(ok);
}

TEST_CASE("BleFrame waits for the full payload across ATT fragments") {
    unsigned char payload[5] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    unsigned char framed[7];
    size_t framed_size = 0;
    TeslaBLE::Common::PrependLength(payload, sizeof(payload), framed, &framed_size);

    TeslaBLE::BleFrame frame;
    REQUIRE(frame.Add(framed, 4) == TeslaBLE::BleFrame::NEED_MORE);
    REQUIRE(frame.Add(framed + 4, 3) == TeslaBLE::BleFrame::COMPLETE);
    REQUIRE(frame.PayloadSize() == 5);
    REQUIRE(memcmp(frame.Payload(), payload, 5) == 0);
}

TEST_CASE("BleFrame does not complete after the second fragment if more remain") {
    unsigned char payload[6] = {1, 2, 3, 4, 5, 6};
    unsigned char framed[8];
    size_t framed_size = 0;
    TeslaBLE::Common::PrependLength(payload, sizeof(payload), framed, &framed_size);

    TeslaBLE::BleFrame frame;
    REQUIRE(frame.Add(framed, 4) == TeslaBLE::BleFrame::NEED_MORE);
    REQUIRE(frame.Add(framed + 4, 2) == TeslaBLE::BleFrame::NEED_MORE);
    REQUIRE(frame.Add(framed + 6, 2) == TeslaBLE::BleFrame::COMPLETE);
    REQUIRE(frame.PayloadSize() == 6);
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
