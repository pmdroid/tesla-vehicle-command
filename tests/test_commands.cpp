#include <catch2/catch_test_macros.hpp>

#include <car_server.pb.h>
#include <carserver.h>
#include <pb_decode.h>
#include <security.h>
#include <shared.h>
#include <vcsec.pb.h>

#include "hex.h"

TEST_CASE("TurnOnClimate encodes Tesla HVAC-on protobuf") {
    unsigned char buffer[64];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::TurnOnClimate(buffer, &size) == ResultCode::SUCCESS);
    REQUIRE(size > 0);
    auto expected = ParseHex("120452020801");
    REQUIRE(std::vector<uint8_t>(buffer, buffer + size) == expected);
}

TEST_CASE("TurnOnClimate decodes as hvacAutoAction power_on") {
    unsigned char buffer[64];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::TurnOnClimate(buffer, &size) == ResultCode::SUCCESS);

    CarServer_Action action = CarServer_Action_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(buffer, size);
    REQUIRE(pb_decode(&stream, CarServer_Action_fields, &action));
    REQUIRE(action.which_action_msg == CarServer_Action_vehicleAction_tag);
    REQUIRE(action.action_msg.vehicleAction.which_vehicle_action_msg ==
            CarServer_VehicleAction_hvacAutoAction_tag);
    REQUIRE(action.action_msg.vehicleAction.vehicle_action_msg.hvacAutoAction.power_on);
}

TEST_CASE("Lock encodes RKE_ACTION_LOCK") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::Lock(buffer, &size) == ResultCode::SUCCESS);

    VCSEC_UnsignedMessage message = VCSEC_UnsignedMessage_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(buffer, size);
    REQUIRE(pb_decode(&stream, VCSEC_UnsignedMessage_fields, &message));
    REQUIRE(message.which_sub_message == VCSEC_UnsignedMessage_RKEAction_tag);
    REQUIRE(message.sub_message.RKEAction == VCSEC_RKEAction_E_RKE_ACTION_LOCK);
}

TEST_CASE("StopCharging encodes stop not start") {
    unsigned char buffer[64];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::StopCharging(buffer, &size) == ResultCode::SUCCESS);

    CarServer_Action action = CarServer_Action_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(buffer, size);
    REQUIRE(pb_decode(&stream, CarServer_Action_fields, &action));
    REQUIRE(action.action_msg.vehicleAction.which_vehicle_action_msg ==
            CarServer_VehicleAction_chargingStartStopAction_tag);
    REQUIRE(action.action_msg.vehicleAction.vehicle_action_msg.chargingStartStopAction.which_charging_action ==
            CarServer_ChargingStartStopAction_stop_tag);
}

TEST_CASE("CloseChargePort encodes chargePortDoorClose") {
    unsigned char buffer[64];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::CloseChargePort(buffer, &size) == ResultCode::SUCCESS);

    CarServer_Action action = CarServer_Action_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(buffer, size);
    REQUIRE(pb_decode(&stream, CarServer_Action_fields, &action));
    REQUIRE(action.action_msg.vehicleAction.which_vehicle_action_msg ==
            CarServer_VehicleAction_chargePortDoorClose_tag);
}

TEST_CASE("Unlock encodes RKE_ACTION_UNLOCK") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::Unlock(buffer, &size) == ResultCode::SUCCESS);

    VCSEC_UnsignedMessage message = VCSEC_UnsignedMessage_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(buffer, size);
    REQUIRE(pb_decode(&stream, VCSEC_UnsignedMessage_fields, &message));
    REQUIRE(message.which_sub_message == VCSEC_UnsignedMessage_RKEAction_tag);
    REQUIRE(message.sub_message.RKEAction == VCSEC_RKEAction_E_RKE_ACTION_UNLOCK);
}
