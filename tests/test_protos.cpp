#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>

#include <car_server.pb.h>
#include <carserver.h>
#include <keys.pb.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <vcsec.pb.h>
#include <shared.h>
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

static CarServer_Response DecodeVehicleDataFixture(CarServer_VehicleData data) {
    CarServer_Response response = CarServer_Response_init_zero;
    response.which_response_msg = CarServer_Response_vehicleData_tag;
    response.response_msg.vehicleData = data;
    unsigned char buffer[1024];
    pb_ostream_t out = pb_ostream_from_buffer(buffer, sizeof buffer);
    REQUIRE(pb_encode(&out, CarServer_Response_fields, &response));
    CarServer_Response decoded = CarServer_Response_init_zero;
    REQUIRE(TeslaBLE::Common::DecodeCarServerResponse(buffer, out.bytes_written, &decoded) ==
            ResultCode::SUCCESS);
    return decoded;
}

TEST_CASE("DecodeCarServerResponse reads drive speed") {
    CarServer_VehicleData data = CarServer_VehicleData_init_zero;
    data.has_drive_state = true;
    data.drive_state.which_optional_speed_float = CarServer_DriveState_speed_float_tag;
    data.drive_state.optional_speed_float.speed_float = 42.5f;
    auto decoded = DecodeVehicleDataFixture(data);
    REQUIRE(decoded.response_msg.vehicleData.has_drive_state);
    REQUIRE(decoded.response_msg.vehicleData.drive_state.optional_speed_float.speed_float == 42.5f);
}

TEST_CASE("DecodeCarServerResponse reads location latitude") {
    CarServer_VehicleData data = CarServer_VehicleData_init_zero;
    data.has_location_state = true;
    data.location_state.which_optional_latitude = CarServer_LocationState_latitude_tag;
    data.location_state.optional_latitude.latitude = 37.4f;
    auto decoded = DecodeVehicleDataFixture(data);
    REQUIRE(decoded.response_msg.vehicleData.location_state.optional_latitude.latitude == 37.4f);
}

TEST_CASE("DecodeCarServerResponse reads closures locked") {
    CarServer_VehicleData data = CarServer_VehicleData_init_zero;
    data.has_closures_state = true;
    data.closures_state.which_optional_locked = CarServer_ClosuresState_locked_tag;
    data.closures_state.optional_locked.locked = true;
    auto decoded = DecodeVehicleDataFixture(data);
    REQUIRE(decoded.response_msg.vehicleData.closures_state.optional_locked.locked);
}

TEST_CASE("DecodeCarServerResponse reads software version") {
    CarServer_VehicleData data = CarServer_VehicleData_init_zero;
    data.has_software_update_state = true;
    data.software_update_state.which_optional_version = CarServer_SoftwareUpdateState_version_tag;
    strncpy(data.software_update_state.optional_version.version, "2025.44",
            sizeof(data.software_update_state.optional_version.version) - 1);
    auto decoded = DecodeVehicleDataFixture(data);
    REQUIRE(std::string(decoded.response_msg.vehicleData.software_update_state.optional_version.version) ==
            "2025.44");
}

TEST_CASE("DecodeCarServerResponse reads parental controls active") {
    CarServer_VehicleData data = CarServer_VehicleData_init_zero;
    data.has_parental_controls_state = true;
    data.parental_controls_state.which_optional_parental_controls_active =
        CarServer_ParentalControlsState_parental_controls_active_tag;
    data.parental_controls_state.optional_parental_controls_active.parental_controls_active = true;
    auto decoded = DecodeVehicleDataFixture(data);
    REQUIRE(decoded.response_msg.vehicleData.parental_controls_state.optional_parental_controls_active
                .parental_controls_active);
}

TEST_CASE("DecodeCarServerResponse reads tire pressure") {
    CarServer_VehicleData data = CarServer_VehicleData_init_zero;
    data.has_tire_pressure_state = true;
    data.tire_pressure_state.which_optional_tpms_pressure_fl = CarServer_TirePressureState_tpms_pressure_fl_tag;
    data.tire_pressure_state.optional_tpms_pressure_fl.tpms_pressure_fl = 2.8f;
    auto decoded = DecodeVehicleDataFixture(data);
    REQUIRE(decoded.response_msg.vehicleData.tire_pressure_state.optional_tpms_pressure_fl.tpms_pressure_fl ==
            2.8f);
}
