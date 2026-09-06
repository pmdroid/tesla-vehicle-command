#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>
#include <vector>

#include <authenticator.h>
#include <shared.h>
#include <universal_message.pb.h>

#include "hex.h"

TEST_CASE("ECDH shared key matches Tesla protocol.md test keys") {
    const unsigned char client_pem[] =
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEICU4zcKal8GcHpmmN9bPT4yXDBGLVu3h5jI+bRYsSzDboAoGCCqGSM49\n"
            "AwEHoUQDQgAEsra8aMLaBmXOZWgVWUmWxiOU7di+qQX+eBp1T+aoRacUMwkC8iXp\n"
            "Jp1GbgWzSZgf2p2FzCPG+0RKpztikQXcbg==\n"
            "-----END EC PRIVATE KEY-----\n";
    auto vehicle_public = ParseHex(
            "04c7a1f47138486aa4729971494878d33b1a24e39571f748a6e16c5955b3d877d3a6aaa0e955166474af5d32c410f439a2234137ad1bb085fd4e8813c958f11d97");
    auto expected_k = ParseHex("1b2fce19967b79db696f909cff89ea9a");

    TeslaBLE::Authenticator authenticator;
    REQUIRE(authenticator.LoadPrivateKey(client_pem, sizeof(client_pem)) == ResultCode::SUCCESS);
    REQUIRE(authenticator.LoadTeslaPublicKey(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
                vehicle_public.data(),
                vehicle_public.size()) == ResultCode::SUCCESS);

    unsigned char shared[16];
    REQUIRE(authenticator.GetSharedSecret(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT, shared, sizeof(shared)) ==
            ResultCode::SUCCESS);
    REQUIRE(std::vector<uint8_t>(shared, shared + 16) == expected_k);
    authenticator.Cleanup();
}

TEST_CASE("RandomBytes fills buffer and is not all zeros") {
    unsigned char a[16];
    unsigned char b[16];
    REQUIRE(TeslaBLE::Common::RandomBytes(a, sizeof(a)) == ResultCode::SUCCESS);
    REQUIRE(TeslaBLE::Common::RandomBytes(b, sizeof(b)) == ResultCode::SUCCESS);
    bool a_nonzero = false;
    for (unsigned char byte: a) {
        if (byte != 0) {
            a_nonzero = true;
            break;
        }
    }
    REQUIRE(a_nonzero);
    REQUIRE(memcmp(a, b, sizeof(a)) != 0);
}
