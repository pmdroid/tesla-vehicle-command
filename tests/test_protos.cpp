#include <catch2/catch_test_macros.hpp>

#include <car_server.pb.h>
#include <carserver.h>
#include <keys.pb.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <vcsec.pb.h>
#include <vehicle.pb.h>

#include "hex.h"

TEST_CASE("TurnOnClimate still matches Tesla HVAC-on vector after proto sync") {
    unsigned char buffer[64];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::TurnOnClimate(buffer, &size) == ResultCode::SUCCESS);
    auto expected = ParseHex("120452020801");
    REQUIRE(std::vector<uint8_t>(buffer, buffer + size) == expected);
}

TEST_CASE("GetVehicleData charge category encodes tag 1") {
    CarServer_Action action = CarServer_Action_init_zero;
    action.which_action_msg = CarServer_Action_vehicleAction_tag;
    action.action_msg.vehicleAction.which_vehicle_action_msg =
        CarServer_VehicleAction_getVehicleData_tag;
    action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.has_getChargeState = true;

    unsigned char buffer[64];
    pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof buffer);
    REQUIRE(pb_encode(&stream, CarServer_Action_fields, &action));
    REQUIRE(stream.bytes_written > 0);

    CarServer_Action decoded = CarServer_Action_init_zero;
    pb_istream_t in = pb_istream_from_buffer(buffer, stream.bytes_written);
    REQUIRE(pb_decode(&in, CarServer_Action_fields, &decoded));
    REQUIRE(decoded.which_action_msg == CarServer_Action_vehicleAction_tag);
    REQUIRE(decoded.action_msg.vehicleAction.which_vehicle_action_msg ==
            CarServer_VehicleAction_getVehicleData_tag);
    REQUIRE(decoded.action_msg.vehicleAction.vehicle_action_msg.getVehicleData.has_getChargeState);
}

TEST_CASE("Response vehicleData is field 2") {
    REQUIRE(CarServer_Response_vehicleData_tag == 2);
}

TEST_CASE("ROLE_GUEST is 8") {
    REQUIRE(Keys_Role_ROLE_GUEST == 8);
}

TEST_CASE("VCSEC whitelist local-entity cancelled is 28") {
    REQUIRE(VCSEC_WhitelistOperation_information_E_WHITELISTOPERATION_INFORMATION_LOCAL_ENTITY_AUTH_FAILED_CANCELLED ==
            28);
}

TEST_CASE("VehicleData C struct stays under 4 KiB") {
    REQUIRE(sizeof(CarServer_VehicleData) <= 4096);
}

TEST_CASE("single-category encoded maxima fit BLE 1024-byte payload") {
    REQUIRE(CarServer_ChargeState_size <= 1024);
    REQUIRE(CarServer_ClimateState_size <= 1024);
    REQUIRE(CarServer_DriveState_size <= 1024);
    REQUIRE(CarServer_LocationState_size <= 1024);
    REQUIRE(CarServer_ClosuresState_size <= 1024);
}
