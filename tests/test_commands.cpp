#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstring>

#include <authenticator.h>
#include <car_server.pb.h>
#include <carserver.h>
#include <keys.pb.h>
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

TEST_CASE("GetWhitelistInfo encodes GET_WHITELIST_INFO") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::GetWhitelistInfo(buffer, &size) == ResultCode::SUCCESS);
    auto message = DecodeUnsigned(buffer, size);
    REQUIRE(message.which_sub_message == VCSEC_UnsignedMessage_InformationRequest_tag);
    REQUIRE(message.sub_message.InformationRequest.informationRequestType ==
            VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO);
}

TEST_CASE("GetWhitelistEntryInfo encodes slot") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::GetWhitelistEntryInfo(3, buffer, &size) == ResultCode::SUCCESS);
    auto message = DecodeUnsigned(buffer, size);
    REQUIRE(message.sub_message.InformationRequest.informationRequestType ==
            VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_ENTRY_INFO);
    REQUIRE(message.sub_message.InformationRequest.which_key == VCSEC_InformationRequest_slot_tag);
    REQUIRE(message.sub_message.InformationRequest.key.slot == 3);
}

TEST_CASE("RemoveKey encodes the public key") {
    unsigned char pubkey[65];
    memset(pubkey, 0x04, sizeof pubkey);
    unsigned char buffer[128];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::RemoveKey(pubkey, sizeof pubkey, buffer, &size) == ResultCode::SUCCESS);
    auto message = DecodeUnsigned(buffer, size);
    REQUIRE(message.which_sub_message == VCSEC_UnsignedMessage_WhitelistOperation_tag);
    REQUIRE(message.sub_message.WhitelistOperation.which_sub_message ==
            VCSEC_WhitelistOperation_removePublicKeyFromWhitelist_tag);
    REQUIRE(message.sub_message.WhitelistOperation.sub_message.removePublicKeyFromWhitelist.PublicKeyRaw.size ==
            65);
    REQUIRE(message.sub_message.WhitelistOperation.sub_message.removePublicKeyFromWhitelist.PublicKeyRaw.bytes[0] ==
            0x04);
}

TEST_CASE("RemoveKey rejects an empty key") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::Security::RemoveKey(nullptr, 65, buffer, &size) == ResultCode::ERROR);
    unsigned char pubkey[1] = {0};
    REQUIRE(TeslaBLE::Security::RemoveKey(pubkey, 0, buffer, &size) == ResultCode::ERROR);
}

TEST_CASE("BuildKeyWhitelistMessage accepts ROLE_GUEST") {
    const unsigned char client_pem[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEICU4zcKal8GcHpmmN9bPT4yXDBGLVu3h5jI+bRYsSzDboAoGCCqGSM49\n"
        "AwEHoUQDQgAEsra8aMLaBmXOZWgVWUmWxiOU7di+qQX+eBp1T+aoRacUMwkC8iXp\n"
        "Jp1GbgWzSZgf2p2FzCPG+0RKpztikQXcbg==\n"
        "-----END EC PRIVATE KEY-----\n";
    TeslaBLE::Authenticator authenticator;
    REQUIRE(authenticator.LoadPrivateKey(client_pem, sizeof(client_pem)) == ResultCode::SUCCESS);

    unsigned char buffer[256];
    size_t size = 0;
    REQUIRE(authenticator.BuildKeyWhitelistMessage(Keys_Role_ROLE_GUEST,
                                                   VCSEC_KeyFormFactor_KEY_FORM_FACTOR_ANDROID_DEVICE, buffer,
                                                   &size) == ResultCode::SUCCESS);
    REQUIRE(size > 2);

    VCSEC_ToVCSECMessage envelope = VCSEC_ToVCSECMessage_init_zero;
    pb_istream_t envelope_stream = pb_istream_from_buffer(buffer + 2, size - 2);
    REQUIRE(pb_decode(&envelope_stream, VCSEC_ToVCSECMessage_fields, &envelope));
    REQUIRE(envelope.has_signedMessage);

    VCSEC_UnsignedMessage inner = VCSEC_UnsignedMessage_init_zero;
    pb_istream_t inner_stream = pb_istream_from_buffer(envelope.signedMessage.protobufMessageAsBytes.bytes,
                                                       envelope.signedMessage.protobufMessageAsBytes.size);
    REQUIRE(pb_decode(&inner_stream, VCSEC_UnsignedMessage_fields, &inner));
    REQUIRE(inner.sub_message.WhitelistOperation.sub_message.addKeyToWhitelistAndAddPermissions.keyRole ==
            Keys_Role_ROLE_GUEST);
}

static CarServer_Action DecodeAction(unsigned char *buffer, size_t size) {
    CarServer_Action action = CarServer_Action_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(buffer, size);
    REQUIRE(pb_decode(&stream, CarServer_Action_fields, &action));
    return action;
}

TEST_CASE("ChangeClimateTemp encodes driver and passenger celsius") {
    unsigned char buffer[64];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::ChangeClimateTemp(21.5f, 22.0f, buffer, &size) == ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    REQUIRE(action.action_msg.vehicleAction.which_vehicle_action_msg ==
            CarServer_VehicleAction_hvacTemperatureAdjustmentAction_tag);
    const auto &temp = action.action_msg.vehicleAction.vehicle_action_msg.hvacTemperatureAdjustmentAction;
    REQUIRE(temp.driver_temp_celsius == 21.5f);
    REQUIRE(temp.passenger_temp_celsius == 22.0f);
    REQUIRE(temp.has_level);
    REQUIRE(temp.level.which_type == CarServer_HvacTemperatureAdjustmentAction_Temperature_TEMP_MAX_tag);
}

TEST_CASE("SetSteeringWheelHeater encodes power_on") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::SetSteeringWheelHeater(true, buffer, &size) == ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    REQUIRE(action.action_msg.vehicleAction.vehicle_action_msg.hvacSteeringWheelHeaterAction.power_on);
}

TEST_CASE("SetSeatHeater encodes front left high") {
    unsigned char buffer[64];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::SetSeatHeater(TeslaBLE::SeatFrontLeft, TeslaBLE::ClimateHigh, buffer, &size) ==
            ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    const auto &heater = action.action_msg.vehicleAction.vehicle_action_msg.hvacSeatHeaterActions;
    REQUIRE(heater.hvacSeatHeaterAction_count == 1);
    REQUIRE(heater.hvacSeatHeaterAction[0].which_seat_heater_level ==
            CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_SEAT_HEATER_HIGH_tag);
    REQUIRE(heater.hvacSeatHeaterAction[0].which_seat_position ==
            CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_CAR_SEAT_FRONT_LEFT_tag);
}

TEST_CASE("SetSeatCooler encodes front right low") {
    unsigned char buffer[64];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::SetSeatCooler(TeslaBLE::SeatFrontRight, TeslaBLE::ClimateLow, buffer, &size) ==
            ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    const auto &cooler = action.action_msg.vehicleAction.vehicle_action_msg.hvacSeatCoolerActions;
    REQUIRE(cooler.hvacSeatCoolerAction_count == 1);
    REQUIRE(cooler.hvacSeatCoolerAction[0].seat_position ==
            CarServer_HvacSeatCoolerActions_HvacSeatCoolerPosition_E_HvacSeatCoolerPosition_FrontRight);
    REQUIRE(cooler.hvacSeatCoolerAction[0].seat_cooler_level ==
            CarServer_HvacSeatCoolerActions_HvacSeatCoolerLevel_E_HvacSeatCoolerLevel_Low);
}

TEST_CASE("SetSeatCooler rejects a rear seat") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::SetSeatCooler(TeslaBLE::SeatSecondRowLeft, TeslaBLE::ClimateOff, buffer, &size) ==
            ResultCode::ERROR);
}

TEST_CASE("SetClimateKeeperMode encodes dog with override") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::SetClimateKeeperMode(
                CarServer_HvacClimateKeeperAction_ClimateKeeperAction_E_ClimateKeeperAction_Dog, true, buffer,
                &size) == ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    const auto &keeper = action.action_msg.vehicleAction.vehicle_action_msg.hvacClimateKeeperAction;
    REQUIRE(keeper.ClimateKeeperAction ==
            CarServer_HvacClimateKeeperAction_ClimateKeeperAction_E_ClimateKeeperAction_Dog);
    REQUIRE(keeper.manual_override);
}

TEST_CASE("SetBioweaponDefenseMode encodes on") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::SetBioweaponDefenseMode(true, false, buffer, &size) == ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    REQUIRE(action.action_msg.vehicleAction.vehicle_action_msg.hvacBioweaponModeAction.on);
}

TEST_CASE("SetCabinOverheatProtection encodes fan_only") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::SetCabinOverheatProtection(true, true, buffer, &size) == ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    REQUIRE(action.action_msg.vehicleAction.vehicle_action_msg.setCabinOverheatProtectionAction.fan_only);
}

TEST_CASE("SetCopTemp encodes high") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::SetCopTemp(
                CarServer_ClimateState_CopActivationTemp_CopActivationTempHigh, buffer, &size) ==
            ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    REQUIRE(action.action_msg.vehicleAction.vehicle_action_msg.setCopTempAction.copActivationTemp ==
            CarServer_ClimateState_CopActivationTemp_CopActivationTempHigh);
}

TEST_CASE("SetPreconditioningMax encodes manual_override") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::SetPreconditioningMax(true, true, buffer, &size) == ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    REQUIRE(action.action_msg.vehicleAction.vehicle_action_msg.hvacSetPreconditioningMaxAction.manual_override);
}

TEST_CASE("AutoSeatClimate encodes front left on") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::AutoSeatClimate(TeslaBLE::SeatFrontLeft, true, buffer, &size) ==
            ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    const auto &seats = action.action_msg.vehicleAction.vehicle_action_msg.autoSeatClimateAction;
    REQUIRE(seats.carseat_count == 1);
    REQUIRE(seats.carseat[0].on);
    REQUIRE(seats.carseat[0].seat_position ==
            CarServer_AutoSeatClimateAction_AutoSeatPosition_E_AutoSeatPosition_FrontLeft);
}

TEST_CASE("SetChargingAmps encodes amps") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::SetChargingAmps(32, buffer, &size) == ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    REQUIRE(action.action_msg.vehicleAction.vehicle_action_msg.setChargingAmpsAction.charging_amps == 32);
}

TEST_CASE("ChargeMaxRange encodes start_max_range") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::ChargeMaxRange(buffer, &size) == ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    REQUIRE(action.action_msg.vehicleAction.vehicle_action_msg.chargingStartStopAction.which_charging_action ==
            CarServer_ChargingStartStopAction_start_max_range_tag);
}

TEST_CASE("ChargeStandardRange encodes start_standard") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::ChargeStandardRange(buffer, &size) == ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    REQUIRE(action.action_msg.vehicleAction.vehicle_action_msg.chargingStartStopAction.which_charging_action ==
            CarServer_ChargingStartStopAction_start_standard_tag);
}

TEST_CASE("ScheduleCharging encodes minutes from midnight") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::ScheduleCharging(true, 120, buffer, &size) == ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    REQUIRE(action.action_msg.vehicleAction.vehicle_action_msg.scheduledChargingAction.enabled);
    REQUIRE(action.action_msg.vehicleAction.vehicle_action_msg.scheduledChargingAction.charging_time == 120);
}

TEST_CASE("ScheduleDeparture encodes all-week preconditioning") {
    unsigned char buffer[64];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::ScheduleDeparture(480, 360, TeslaBLE::ChargingPolicyAllDays,
                                                   TeslaBLE::ChargingPolicyWeekdays, buffer, &size) ==
            ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    const auto &dep = action.action_msg.vehicleAction.vehicle_action_msg.scheduledDepartureAction;
    REQUIRE(dep.enabled);
    REQUIRE(dep.departure_time == 480);
    REQUIRE(dep.has_preconditioning_times);
    REQUIRE(dep.preconditioning_times.which_times == CarServer_PreconditioningTimes_all_week_tag);
    REQUIRE(dep.has_off_peak_charging_times);
    REQUIRE(dep.off_peak_charging_times.which_times == CarServer_OffPeakChargingTimes_weekdays_tag);
}

TEST_CASE("ScheduleDeparture rejects an invalid departure time") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::ScheduleDeparture(24 * 60 + 1, 0, TeslaBLE::ChargingPolicyOff,
                                                   TeslaBLE::ChargingPolicyOff, buffer, &size) == ResultCode::ERROR);
}

TEST_CASE("ClearScheduledDeparture encodes enabled false") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::ClearScheduledDeparture(buffer, &size) == ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    REQUIRE_FALSE(action.action_msg.vehicleAction.vehicle_action_msg.scheduledDepartureAction.enabled);
}

TEST_CASE("GetNearbyCharging encodes Tesla BLE defaults") {
    unsigned char buffer[32];
    size_t size = 0;
    REQUIRE(TeslaBLE::CarServer::GetNearbyCharging(buffer, &size) == ResultCode::SUCCESS);
    auto action = DecodeAction(buffer, size);
    const auto &sites = action.action_msg.vehicleAction.vehicle_action_msg.getNearbyChargingSites;
    REQUIRE(sites.include_meta_data);
    REQUIRE(sites.radius == 200);
    REQUIRE(sites.count == 10);
}
