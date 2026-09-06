#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <vector>

#include <authenticator.h>
#include <pb_encode.h>
#include <security.h>
#include <session.h>
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

    std::vector<uint8_t> EncodeSessionInfo(const Signatures_SessionInfo &info) {
        uint8_t buffer[Signatures_SessionInfo_size];
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
        REQUIRE(pb_encode(&stream, Signatures_SessionInfo_fields, &info));
        return {buffer, buffer + stream.bytes_written};
    }

    Signatures_SessionInfo TeslaVehicleSession() {
        Signatures_SessionInfo info = Signatures_SessionInfo_init_zero;
        auto public_key = ParseHex(
                "04c7a1f47138486aa4729971494878d33b1a24e39571f748a6e16c5955b3d877d3a6aaa0e955166474af5d32c410f439a2234137ad1bb085fd4e8813c958f11d97");
        auto epoch = ParseHex("4c463f9cc0d3d26906e982ed224adde6");
        memcpy(info.publicKey.bytes, public_key.data(), public_key.size());
        info.publicKey.size = public_key.size();
        memcpy(info.epoch, epoch.data(), epoch.size());
        info.counter = 6;
        info.clock_time = 2650;
        info.status = Signatures_Session_Info_Status_SESSION_INFO_STATUS_OK;
        return info;
    }
}

TEST_CASE("UpdateSessionInfo rejects KEY_NOT_ON_WHITELIST after decode") {
    Signatures_SessionInfo info = Signatures_SessionInfo_init_zero;
    info.status = Signatures_Session_Info_Status_SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST;
    auto encoded = EncodeSessionInfo(info);

    TeslaBLE::Session session;
    TeslaBLE::Authenticator authenticator;
    session.LoadAuthenticator(&authenticator);
    unsigned char tag[32] = {};
    REQUIRE(session.UpdateSessionInfo(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT, encoded.data(), encoded.size(), tag,
                sizeof(tag)) == ResultCode::SESSION_INFO_KEY_NOT_WHITELISTED);
}

TEST_CASE("session validity is per domain") {
    TeslaBLE::Authenticator authenticator;
    REQUIRE(authenticator.LoadPrivateKey(kClientPem, sizeof(kClientPem)) == ResultCode::SUCCESS);

    TeslaBLE::Session session;
    session.LoadAuthenticator(&authenticator);
    unsigned char vin[17];
    memcpy(vin, "5YJ30123456789ABC", 17);
    session.SetVIN(vin);
    session.GenerateRoutingAddress();

    auto encoded = ParseHex(
            "0806124104c7a1f47138486aa4729971494878d33b1a24e39571f748a6e16c5955b3d877d3a6aaa0e955166474af5d32c410f439a2234137ad1bb085fd4e8813c958f11d971a104c463f9cc0d3d26906e982ed224adde6255a0a0000");
    auto challenge = ParseHex("1588d5a30eabc6f8fc9a951b11f6fd11");
    auto tag = ParseHex("996c1fe38331be138f8039c194b14db2198846ed7d8251e6749284d7b32ea002");
    session.SetRequestUuid(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, challenge.data(),
                           challenge.size());
    REQUIRE(session.UpdateSessionInfo(
                UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, encoded.data(), encoded.size(),
                tag.data(), tag.size()) == ResultCode::SUCCESS);

    unsigned char action[32];
    size_t action_size = 0;
    REQUIRE(TeslaBLE::Security::Lock(action, &action_size) == ResultCode::SUCCESS);

    unsigned char out[512];
    size_t out_size = 0;
    REQUIRE(session.BuildRoutableMessage(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT, action, action_size, out, &out_size) ==
            ResultCode::SESSION_INFO_NOT_LOADED);
    REQUIRE(session.BuildRoutableMessage(
                UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, action, action_size, out, &out_size) ==
            ResultCode::SUCCESS);
    authenticator.Cleanup();
}

TEST_CASE("UpdateSessionInfo accepts Tesla protocol.md session info HMAC") {
    TeslaBLE::Authenticator authenticator;
    REQUIRE(authenticator.LoadPrivateKey(kClientPem, sizeof(kClientPem)) == ResultCode::SUCCESS);

    TeslaBLE::Session session;
    session.LoadAuthenticator(&authenticator);
    unsigned char vin[17];
    memcpy(vin, "5YJ30123456789ABC", 17);
    session.SetVIN(vin);

    auto encoded = ParseHex(
            "0806124104c7a1f47138486aa4729971494878d33b1a24e39571f748a6e16c5955b3d877d3a6aaa0e955166474af5d32c410f439a2234137ad1bb085fd4e8813c958f11d971a104c463f9cc0d3d26906e982ed224adde6255a0a0000");
    auto challenge = ParseHex("1588d5a30eabc6f8fc9a951b11f6fd11");
    auto tag = ParseHex("996c1fe38331be138f8039c194b14db2198846ed7d8251e6749284d7b32ea002");
    session.SetRequestUuid(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, challenge.data(),
                           challenge.size());
    REQUIRE(session.UpdateSessionInfo(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT, encoded.data(), encoded.size(),
                tag.data(), tag.size()) == ResultCode::SUCCESS);
    authenticator.Cleanup();
}

TEST_CASE("UpdateSessionInfo rejects a bad session info HMAC") {
    TeslaBLE::Authenticator authenticator;
    REQUIRE(authenticator.LoadPrivateKey(kClientPem, sizeof(kClientPem)) == ResultCode::SUCCESS);

    TeslaBLE::Session session;
    session.LoadAuthenticator(&authenticator);
    unsigned char vin[17];
    memcpy(vin, "5YJ30123456789ABC", 17);
    session.SetVIN(vin);

    auto encoded = ParseHex(
            "0806124104c7a1f47138486aa4729971494878d33b1a24e39571f748a6e16c5955b3d877d3a6aaa0e955166474af5d32c410f439a2234137ad1bb085fd4e8813c958f11d971a104c463f9cc0d3d26906e982ed224adde6255a0a0000");
    auto challenge = ParseHex("1588d5a30eabc6f8fc9a951b11f6fd11");
    auto tag = ParseHex("0000000000000000000000000000000000000000000000000000000000000000");
    session.SetRequestUuid(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, challenge.data(),
                           challenge.size());
    REQUIRE(session.UpdateSessionInfo(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT, encoded.data(), encoded.size(),
                tag.data(), tag.size()) == ResultCode::SESSION_INFO_HMAC_INVALID);
    unsigned char shared[16];
    REQUIRE(authenticator.GetSharedSecret(
                UniversalMessage_Domain_DOMAIN_INFOTAINMENT, shared, sizeof(shared)) ==
            ResultCode::SESSION_INFO_NOT_LOADED);
    authenticator.Cleanup();
}
