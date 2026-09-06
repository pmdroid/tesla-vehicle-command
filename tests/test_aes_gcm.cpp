#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <vector>

#include <authenticator.h>
#include <metadata.h>
#include <shared.h>
#include <signatures.pb.h>
#include <universal_message.pb.h>

#include "hex.h"

namespace {
    const unsigned char kClientPem[] =
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEICU4zcKal8GcHpmmN9bPT4yXDBGLVu3h5jI+bRYsSzDboAoGCCqGSM49\n"
            "AwEHoUQDQgAEsra8aMLaBmXOZWgVWUmWxiOU7di+qQX+eBp1T+aoRacUMwkC8iXp\n"
            "Jp1GbgWzSZgf2p2FzCPG+0RKpztikQXcbg==\n"
            "-----END EC PRIVATE KEY-----\n";
}

TEST_CASE("AES-GCM HVAC-on matches Tesla protocol.md vector with FLAG_ENCRYPT_RESPONSE") {
    unsigned char vin[17];
    memcpy(vin, "5YJ30123456789ABC", 17);
    auto epoch = ParseHex("4c463f9cc0d3d26906e982ed224adde6");
    auto nonce = ParseHex("dbf79447fa156674dae1caed");
    auto plaintext = ParseHex("120452020801");
    auto expected_ct = ParseHex("38038e8c0f2e");
    auto expected_tag = ParseHex("c228e0ff64991481db3a7bbc133696c5");
    auto vehicle_public = ParseHex(
            "04c7a1f47138486aa4729971494878d33b1a24e39571f748a6e16c5955b3d877d3a6aaa0e955166474af5d32c410f439a2234137ad1bb085fd4e8813c958f11d97");
    const uint32_t flags = 1u << UniversalMessage_Flags_FLAG_ENCRYPT_RESPONSE;

    TeslaBLE::MetaData meta;
    REQUIRE(meta.Start() == ResultCode::SUCCESS);
    REQUIRE(meta.BuildMetadata(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
                Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED, vin, 2655, 7,
                epoch.data(), flags) == ResultCode::SUCCESS);
    unsigned char checksum[32];
    meta.Checksum(checksum, Signatures_Tag_TAG_END);

    TeslaBLE::Authenticator authenticator;
    REQUIRE(authenticator.LoadPrivateKey(kClientPem, sizeof(kClientPem)) == ResultCode::SUCCESS);
    REQUIRE(authenticator.LoadTeslaPublicKey(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT, vehicle_public.data(),
                vehicle_public.size()) == ResultCode::SUCCESS);

    unsigned char ciphertext[32];
    size_t ciphertext_size = 0;
    unsigned char tag[16];
    REQUIRE(authenticator.EncryptWithNonce(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT, plaintext.data(), plaintext.size(),
                checksum, nonce.data(), nonce.size(), ciphertext, sizeof(ciphertext),
                &ciphertext_size, tag) == ResultCode::SUCCESS);
    REQUIRE(std::vector<uint8_t>(ciphertext, ciphertext + ciphertext_size) == expected_ct);
    REQUIRE(std::vector<uint8_t>(tag, tag + 16) == expected_tag);

    unsigned char decrypted[32];
    size_t decrypted_size = 0;
    REQUIRE(authenticator.Decrypt(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT, nonce.data(), nonce.size(), ciphertext,
                ciphertext_size, checksum, tag, sizeof(tag), decrypted, sizeof(decrypted),
                &decrypted_size) == ResultCode::SUCCESS);
    REQUIRE(std::vector<uint8_t>(decrypted, decrypted + decrypted_size) == plaintext);
    authenticator.Cleanup();
}
