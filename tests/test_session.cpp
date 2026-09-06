#include <catch2/catch_test_macros.hpp>

#include <cstring>

#include <authenticator.h>
#include <security.h>
#include <session.h>
#include <shared.h>
#include <signatures.pb.h>
#include <universal_message.pb.h>

#include "hex.h"

TEST_CASE("ExportSessionInfo then ImportSessionInfo restores a usable session") {
    const unsigned char client_pem[] =
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEICU4zcKal8GcHpmmN9bPT4yXDBGLVu3h5jI+bRYsSzDboAoGCCqGSM49\n"
            "AwEHoUQDQgAEsra8aMLaBmXOZWgVWUmWxiOU7di+qQX+eBp1T+aoRacUMwkC8iXp\n"
            "Jp1GbgWzSZgf2p2FzCPG+0RKpztikQXcbg==\n"
            "-----END EC PRIVATE KEY-----\n";

    TeslaBLE::Authenticator authenticator;
    REQUIRE(authenticator.LoadPrivateKey(client_pem, sizeof(client_pem)) == ResultCode::SUCCESS);
    TeslaBLE::Session session;
    session.LoadAuthenticator(&authenticator);
    unsigned char vin[17];
    memcpy(vin, "5YJ30123456789ABC", 17);
    session.SetVIN(vin);
    REQUIRE(session.GenerateRoutingAddress() == ResultCode::SUCCESS);

    auto encoded = ParseHex(
            "0806124104c7a1f47138486aa4729971494878d33b1a24e39571f748a6e16c5955b3d877d3a6aaa0e955166474af5d32c410f439a2234137ad1bb085fd4e8813c958f11d971a104c463f9cc0d3d26906e982ed224adde6255a0a0000");
    auto challenge = ParseHex("1588d5a30eabc6f8fc9a951b11f6fd11");
    auto tag = ParseHex("996c1fe38331be138f8039c194b14db2198846ed7d8251e6749284d7b32ea002");
    session.SetRequestUuid(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, challenge.data(),
                           challenge.size());
    REQUIRE(session.UpdateSessionInfo(
                UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, encoded.data(), encoded.size(),
                tag.data(), tag.size()) == ResultCode::SUCCESS);

    unsigned char exported[Signatures_SessionInfo_size];
    size_t exported_size = 0;
    REQUIRE(session.ExportSessionInfo(
                UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, exported, &exported_size) ==
            ResultCode::SUCCESS);

    TeslaBLE::Authenticator authenticator2;
    REQUIRE(authenticator2.LoadPrivateKey(client_pem, sizeof(client_pem)) == ResultCode::SUCCESS);
    TeslaBLE::Session session2;
    session2.LoadAuthenticator(&authenticator2);
    session2.SetVIN(vin);
    REQUIRE(session2.GenerateRoutingAddress() == ResultCode::SUCCESS);
    REQUIRE(session2.ImportSessionInfo(
                UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, exported, exported_size) ==
            ResultCode::SUCCESS);

    unsigned char action[32];
    size_t action_size = 0;
    REQUIRE(TeslaBLE::Security::Lock(action, &action_size) == ResultCode::SUCCESS);
    unsigned char out[512];
    size_t out_size = 0;
    REQUIRE(session2.BuildRoutableMessage(
                UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, action, action_size, out,
                &out_size) == ResultCode::SUCCESS);
    REQUIRE(out_size > 2);
}
