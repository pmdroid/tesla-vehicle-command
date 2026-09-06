#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <car_server.pb.h>
#include <carserver.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <security.h>
#include <shared.h>
#include <vcsec.pb.h>

#include "hex.h"

static bool CategoryFlagSet(const CarServer_GetVehicleData &data,
                            TeslaBLE::VehicleDataCategory category) {
    switch (category) {
        case TeslaBLE::VehicleDataCharge:
            return data.has_getChargeState;
        case TeslaBLE::VehicleDataClimate:
            return data.has_getClimateState;
        case TeslaBLE::VehicleDataDrive:
            return data.has_getDriveState;
        case TeslaBLE::VehicleDataLocation:
            return data.has_getLocationState;
        case TeslaBLE::VehicleDataClosures:
            return data.has_getClosuresState;
        case TeslaBLE::VehicleDataChargeSchedule:
            return data.has_getChargeScheduleState;
        case TeslaBLE::VehicleDataPreconditioningSchedule:
            return data.has_getPreconditioningScheduleState;
        case TeslaBLE::VehicleDataTirePressure:
            return data.has_getTirePressureState;
        case TeslaBLE::VehicleDataMedia:
            return data.has_getMediaState;
        case TeslaBLE::VehicleDataMediaDetail:
            return data.has_getMediaDetailState;
        case TeslaBLE::VehicleDataSoftwareUpdate:
            return data.has_getSoftwareUpdateState;
        case TeslaBLE::VehicleDataParentalControls:
            return data.has_getParentalControlsState;
        default:
            return false;
    }
}

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

TEST_CASE("GetVehicleData encodes one Tesla category") {
    const auto category = GENERATE(
        TeslaBLE::VehicleDataCharge, TeslaBLE::VehicleDataClimate, TeslaBLE::VehicleDataDrive,
        TeslaBLE::VehicleDataLocation, TeslaBLE::VehicleDataClosures,
        TeslaBLE::VehicleDataChargeSchedule, TeslaBLE::VehicleDataPreconditioningSchedule,
        TeslaBLE::VehicleDataTirePressure, TeslaBLE::VehicleDataMedia,
        TeslaBLE::VehicleDataMediaDetail, TeslaBLE::VehicleDataSoftwareUpdate,
        TeslaBLE::VehicleDataParentalControls);

    unsigned char buffer[64];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::GetVehicleData(category, buffer, &size) == ResultCode::SUCCESS);
    REQUIRE(size > 0);

    CarServer_Action action = CarServer_Action_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(buffer, size);
    REQUIRE(pb_decode(&stream, CarServer_Action_fields, &action));
    REQUIRE(action.which_action_msg == CarServer_Action_vehicleAction_tag);
    REQUIRE(action.action_msg.vehicleAction.which_vehicle_action_msg ==
            CarServer_VehicleAction_getVehicleData_tag);

    const auto &data = action.action_msg.vehicleAction.vehicle_action_msg.getVehicleData;
    REQUIRE(CategoryFlagSet(data, category));
    int set_count = 0;
    for (int i = TeslaBLE::VehicleDataCharge; i <= TeslaBLE::VehicleDataParentalControls; ++i) {
        if (CategoryFlagSet(data, static_cast<TeslaBLE::VehicleDataCategory>(i))) {
            ++set_count;
        }
    }
    REQUIRE(set_count == 1);
}

TEST_CASE("GetVehicleData rejects an unknown category") {
    unsigned char buffer[64];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::GetVehicleData(
                static_cast<TeslaBLE::VehicleDataCategory>(99), buffer, &size) ==
            ResultCode::ERROR);
}

TEST_CASE("DecodeCarServerResponse reads charge_limit_soc and climate on") {
    CarServer_Response response = CarServer_Response_init_zero;
    response.which_response_msg = CarServer_Response_vehicleData_tag;
    response.response_msg.vehicleData.has_charge_state = true;
    response.response_msg.vehicleData.charge_state.which_optional_charge_limit_soc =
        CarServer_ChargeState_charge_limit_soc_tag;
    response.response_msg.vehicleData.charge_state.optional_charge_limit_soc.charge_limit_soc = 80;
    response.response_msg.vehicleData.has_climate_state = true;
    response.response_msg.vehicleData.climate_state.which_optional_is_climate_on =
        CarServer_ClimateState_is_climate_on_tag;
    response.response_msg.vehicleData.climate_state.optional_is_climate_on.is_climate_on = true;

    unsigned char buffer[512];
    pb_ostream_t out = pb_ostream_from_buffer(buffer, sizeof buffer);
    REQUIRE(pb_encode(&out, CarServer_Response_fields, &response));

    CarServer_Response decoded = CarServer_Response_init_zero;
    REQUIRE(TeslaBLE::Common::DecodeCarServerResponse(buffer, out.bytes_written, &decoded) ==
            ResultCode::SUCCESS);
    REQUIRE(decoded.which_response_msg == CarServer_Response_vehicleData_tag);
    REQUIRE(decoded.response_msg.vehicleData.has_charge_state);
    REQUIRE(decoded.response_msg.vehicleData.charge_state.which_optional_charge_limit_soc ==
            CarServer_ChargeState_charge_limit_soc_tag);
    REQUIRE(decoded.response_msg.vehicleData.charge_state.optional_charge_limit_soc.charge_limit_soc ==
            80);
    REQUIRE(decoded.response_msg.vehicleData.has_climate_state);
    REQUIRE(decoded.response_msg.vehicleData.climate_state.optional_is_climate_on.is_climate_on);
}

TEST_CASE("DecodeCarServerResponse rejects truncated bytes") {
    unsigned char buffer[] = {0xff, 0xff, 0xff};
    CarServer_Response decoded = CarServer_Response_init_zero;
    REQUIRE(TeslaBLE::Common::DecodeCarServerResponse(buffer, sizeof buffer, &decoded) ==
            ResultCode::NANOPB_DECODE_ERROR);
}

static VCSEC_UnsignedMessage DecodeUnsigned(unsigned char *buffer, size_t size) {
    VCSEC_UnsignedMessage message = VCSEC_UnsignedMessage_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(buffer, size);
    REQUIRE(pb_decode(&stream, VCSEC_UnsignedMessage_fields, &message));
    return message;
}

TEST_CASE("OpenTrunk encodes rearTrunk MOVE") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::OpenTrunk(buffer, &size) == ResultCode::SUCCESS);
    auto message = DecodeUnsigned(buffer, size);
    REQUIRE(message.which_sub_message == VCSEC_UnsignedMessage_closureMoveRequest_tag);
    REQUIRE(message.sub_message.closureMoveRequest.rearTrunk ==
            VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_MOVE);
    REQUIRE(message.sub_message.closureMoveRequest.frontTrunk ==
            VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE);
}

TEST_CASE("CloseTrunk encodes rearTrunk CLOSE") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::CloseTrunk(buffer, &size) == ResultCode::SUCCESS);
    auto message = DecodeUnsigned(buffer, size);
    REQUIRE(message.sub_message.closureMoveRequest.rearTrunk ==
            VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE);
}

TEST_CASE("OpenFrunk encodes frontTrunk MOVE") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::OpenFrunk(buffer, &size) == ResultCode::SUCCESS);
    auto message = DecodeUnsigned(buffer, size);
    REQUIRE(message.sub_message.closureMoveRequest.frontTrunk ==
            VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_MOVE);
}

TEST_CASE("OpenTonneau encodes tonneau OPEN") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::OpenTonneau(buffer, &size) == ResultCode::SUCCESS);
    auto message = DecodeUnsigned(buffer, size);
    REQUIRE(message.sub_message.closureMoveRequest.tonneau ==
            VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN);
}

TEST_CASE("CloseTonneau encodes tonneau CLOSE") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::CloseTonneau(buffer, &size) == ResultCode::SUCCESS);
    auto message = DecodeUnsigned(buffer, size);
    REQUIRE(message.sub_message.closureMoveRequest.tonneau ==
            VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE);
}

TEST_CASE("StopTonneau encodes tonneau STOP") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::StopTonneau(buffer, &size) == ResultCode::SUCCESS);
    auto message = DecodeUnsigned(buffer, size);
    REQUIRE(message.sub_message.closureMoveRequest.tonneau ==
            VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_STOP);
}

TEST_CASE("AutoSecure encodes RKE_ACTION_AUTO_SECURE_VEHICLE") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::AutoSecure(buffer, &size) == ResultCode::SUCCESS);
    auto message = DecodeUnsigned(buffer, size);
    REQUIRE(message.which_sub_message == VCSEC_UnsignedMessage_RKEAction_tag);
    REQUIRE(message.sub_message.RKEAction == VCSEC_RKEAction_E_RKE_ACTION_AUTO_SECURE_VEHICLE);
}

TEST_CASE("RemoteDrive encodes RKE_ACTION_REMOTE_DRIVE") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::RemoteDrive(buffer, &size) == ResultCode::SUCCESS);
    auto message = DecodeUnsigned(buffer, size);
    REQUIRE(message.sub_message.RKEAction == VCSEC_RKEAction_E_RKE_ACTION_REMOTE_DRIVE);
}

TEST_CASE("GetStatus encodes INFORMATION_REQUEST_TYPE_GET_STATUS") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::GetStatus(buffer, &size) == ResultCode::SUCCESS);
    auto message = DecodeUnsigned(buffer, size);
    REQUIRE(message.which_sub_message == VCSEC_UnsignedMessage_InformationRequest_tag);
    REQUIRE(message.sub_message.InformationRequest.informationRequestType ==
            VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS);
}

TEST_CASE("DecodeFromVCSECMessage reads vehicleStatus lock and sleep") {
    VCSEC_FromVCSECMessage status = VCSEC_FromVCSECMessage_init_zero;
    status.which_sub_message = VCSEC_FromVCSECMessage_vehicleStatus_tag;
    status.sub_message.vehicleStatus.vehicleLockState =
        VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_LOCKED;
    status.sub_message.vehicleStatus.vehicleSleepStatus =
        VCSEC_VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_ASLEEP;
    status.sub_message.vehicleStatus.has_closureStatuses = true;
    status.sub_message.vehicleStatus.closureStatuses.rearTrunk =
        VCSEC_ClosureState_E_CLOSURESTATE_CLOSED;

    unsigned char buffer[64];
    pb_ostream_t out = pb_ostream_from_buffer(buffer, sizeof buffer);
    REQUIRE(pb_encode(&out, VCSEC_FromVCSECMessage_fields, &status));

    VCSEC_FromVCSECMessage decoded = VCSEC_FromVCSECMessage_init_zero;
    REQUIRE(TeslaBLE::Common::DecodeFromVCSECMessage(buffer, out.bytes_written, &decoded) ==
            ResultCode::SUCCESS);
    REQUIRE(decoded.which_sub_message == VCSEC_FromVCSECMessage_vehicleStatus_tag);
    REQUIRE(decoded.sub_message.vehicleStatus.vehicleLockState ==
            VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_LOCKED);
    REQUIRE(decoded.sub_message.vehicleStatus.vehicleSleepStatus ==
            VCSEC_VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_ASLEEP);
    REQUIRE(decoded.sub_message.vehicleStatus.closureStatuses.rearTrunk ==
            VCSEC_ClosureState_E_CLOSURESTATE_CLOSED);
}
