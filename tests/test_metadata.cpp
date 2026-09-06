#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <vector>

#include <mbedtls/sha256.h>
#include <metadata.h>
#include <shared.h>
#include <signatures.pb.h>
#include <universal_message.pb.h>

#include "hex.h"

namespace {
    std::vector<uint8_t> Sha256(const std::vector<uint8_t> &input) {
        std::vector<uint8_t> digest(32);
        REQUIRE(mbedtls_sha256(input.data(), input.size(), digest.data(), 0) == 0);
        return digest;
    }
}

TEST_CASE("metadata checksum matches Tesla protocol.md HVAC vector without flags") {
    unsigned char vin[17];
    memcpy(vin, "5YJ30123456789ABC", 17);
    auto epoch = ParseHex("4c463f9cc0d3d26906e982ed224adde6");
    const uint32_t expires_at = 2655;
    const uint32_t counter = 7;

    auto expected_tlv = ParseHex(
        "000105010103021135594a333031323334353637383941424303104c463f9cc0d3d26906e982ed224adde6040400000a5f050400000007ff");
    auto expected = Sha256(expected_tlv);

    TeslaBLE::MetaData meta;
    REQUIRE(meta.Start() == ResultCode::SUCCESS);
    REQUIRE(meta.BuildMetadata(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
                Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                vin,
                expires_at,
                counter,
                epoch.data()) == ResultCode::SUCCESS);

    unsigned char checksum[32];
    meta.Checksum(checksum, Signatures_Tag_TAG_END);
    REQUIRE(std::vector<uint8_t>(checksum, checksum + 32) == expected);
}

TEST_CASE("metadata checksum changes when counter changes") {
    unsigned char vin[17];
    memcpy(vin, "5YJ30123456789ABC", 17);
    auto epoch = ParseHex("4c463f9cc0d3d26906e982ed224adde6");

    TeslaBLE::MetaData a;
    REQUIRE(a.Start() == ResultCode::SUCCESS);
    REQUIRE(a.BuildMetadata(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
                Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                vin, 2655, 7, epoch.data()) == ResultCode::SUCCESS);
    unsigned char checksum_a[32];
    a.Checksum(checksum_a, Signatures_Tag_TAG_END);

    TeslaBLE::MetaData b;
    REQUIRE(b.Start() == ResultCode::SUCCESS);
    REQUIRE(b.BuildMetadata(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
                Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                vin, 2655, 8, epoch.data()) == ResultCode::SUCCESS);
    unsigned char checksum_b[32];
    b.Checksum(checksum_b, Signatures_Tag_TAG_END);

    REQUIRE(std::vector<uint8_t>(checksum_a, checksum_a + 32) !=
            std::vector<uint8_t>(checksum_b, checksum_b + 32));
}
