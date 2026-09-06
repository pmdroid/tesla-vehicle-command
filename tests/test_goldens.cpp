#include <catch2/catch_test_macros.hpp>

#include <fstream>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <carserver.h>
#include <security.h>
#include <shared.h>

#include "hex.h"

#ifndef TESLA_GOLDENS_FILE
#error TESLA_GOLDENS_FILE is required
#endif

static const unsigned char kTeslaTestPubkey[65] = {
    0x04, 0x2a, 0x01, 0xe3, 0x08, 0x84, 0x64, 0xb5, 0xe9, 0xf7, 0x2d, 0x68,
    0x79, 0x52, 0x27, 0xb2, 0xe9, 0x6b, 0xdc, 0x05, 0xb4, 0x79, 0x6d, 0xd5,
    0xa2, 0xcf, 0xc8, 0x6d, 0xa4, 0xde, 0x23, 0x37, 0xb8, 0xb2, 0xaf, 0x69,
    0x65, 0xea, 0xc9, 0x2e, 0x64, 0xc0, 0xfc, 0xdb, 0x8c, 0x5a, 0x07, 0xb7,
    0x64, 0xce, 0x6a, 0x01, 0xf4, 0x91, 0xef, 0xc5, 0x50, 0x88, 0xb5, 0xe1,
    0x98, 0x5f, 0x30, 0x4e, 0x63,
};

static std::map<std::string, std::string> LoadGoldens() {
    std::ifstream in(TESLA_GOLDENS_FILE);
    REQUIRE(in.good());
    std::map<std::string, std::string> out;
    std::string name;
    std::string hex;
    while (in >> name >> hex) {
        REQUIRE(out.insert({name, hex}).second);
    }
    REQUIRE_FALSE(out.empty());
    return out;
}

static void ExpectGolden(const std::map<std::string, std::string> &goldens, std::set<std::string> *seen,
                         const std::string &name, const std::function<int(unsigned char *, size_t *)> &encode) {
    INFO(name);
    REQUIRE(seen->insert(name).second);
    auto it = goldens.find(name);
    REQUIRE(it != goldens.end());
    unsigned char buffer[256];
    size_t size = 0;
    REQUIRE(encode(buffer, &size) == ResultCode::SUCCESS);
    REQUIRE(size > 0);
    REQUIRE(std::vector<uint8_t>(buffer, buffer + size) == ParseHex(it->second));
}

TEST_CASE("C++ encodes match Tesla Go proto.Marshal goldens") {
    const auto goldens = LoadGoldens();
    std::set<std::string> seen;

    ExpectGolden(goldens, &seen, "climate_on", TeslaBLE::CarServer::TurnOnClimate);
    ExpectGolden(goldens, &seen, "climate_off", TeslaBLE::CarServer::TurnOffClimate);
    ExpectGolden(goldens, &seen, "climate_temp", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::ChangeClimateTemp(21.5f, 22.0f, b, n);
    });
    ExpectGolden(goldens, &seen, "steering_wheel", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetSteeringWheelHeater(true, b, n);
    });
    ExpectGolden(goldens, &seen, "seat_heater_fl_high", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetSeatHeater(TeslaBLE::SeatFrontLeft, TeslaBLE::ClimateHigh, b, n);
    });
    ExpectGolden(goldens, &seen, "seat_cooler_fr_low", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetSeatCooler(TeslaBLE::SeatFrontRight, TeslaBLE::ClimateLow, b, n);
    });
    ExpectGolden(goldens, &seen, "climate_keeper_dog", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetClimateKeeperMode(
            CarServer_HvacClimateKeeperAction_ClimateKeeperAction_E_ClimateKeeperAction_Dog, true, b, n);
    });
    ExpectGolden(goldens, &seen, "bioweapon", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetBioweaponDefenseMode(true, false, b, n);
    });
    ExpectGolden(goldens, &seen, "cop_fan", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetCabinOverheatProtection(true, true, b, n);
    });
    ExpectGolden(goldens, &seen, "cop_temp_high", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetCopTemp(CarServer_ClimateState_CopActivationTemp_CopActivationTempHigh, b, n);
    });
    ExpectGolden(goldens, &seen, "precondition_max", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetPreconditioningMax(true, true, b, n);
    });
    ExpectGolden(goldens, &seen, "auto_seat_fl", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::AutoSeatClimate(TeslaBLE::SeatFrontLeft, true, b, n);
    });
    ExpectGolden(goldens, &seen, "charge_start", TeslaBLE::CarServer::StartCharging);
    ExpectGolden(goldens, &seen, "charge_stop", TeslaBLE::CarServer::StopCharging);
    ExpectGolden(goldens, &seen, "charge_limit_80", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetChargingLimit(80, b, n);
    });
    ExpectGolden(goldens, &seen, "charge_amps_32", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetChargingAmps(32, b, n);
    });
    ExpectGolden(goldens, &seen, "charge_max", TeslaBLE::CarServer::ChargeMaxRange);
    ExpectGolden(goldens, &seen, "charge_std", TeslaBLE::CarServer::ChargeStandardRange);
    ExpectGolden(goldens, &seen, "charge_port_open", TeslaBLE::CarServer::OpenChargePort);
    ExpectGolden(goldens, &seen, "charge_port_close", TeslaBLE::CarServer::CloseChargePort);
    ExpectGolden(goldens, &seen, "schedule_charging", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::ScheduleCharging(true, 120, b, n);
    });
    ExpectGolden(goldens, &seen, "schedule_departure", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::ScheduleDeparture(480, 360, TeslaBLE::ChargingPolicyAllDays,
                                                      TeslaBLE::ChargingPolicyWeekdays, b, n);
    });
    ExpectGolden(goldens, &seen, "clear_departure", TeslaBLE::CarServer::ClearScheduledDeparture);
    ExpectGolden(goldens, &seen, "nearby", TeslaBLE::CarServer::GetNearbyCharging);
    ExpectGolden(goldens, &seen, "vent", TeslaBLE::CarServer::Vent);
    ExpectGolden(goldens, &seen, "get_charge_state", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::GetVehicleData(TeslaBLE::VehicleDataCharge, b, n);
    });
    ExpectGolden(goldens, &seen, "honk", TeslaBLE::CarServer::HonkHorn);
    ExpectGolden(goldens, &seen, "flash", TeslaBLE::CarServer::FlashLights);
    ExpectGolden(goldens, &seen, "close_windows", TeslaBLE::CarServer::CloseWindows);
    ExpectGolden(goldens, &seen, "sunroof_80", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetSunroofLevel(80, b, n);
    });
    ExpectGolden(goldens, &seen, "sentry_on", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetSentryMode(true, b, n);
    });
    ExpectGolden(goldens, &seen, "valet_1234", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::EnableValetMode("1234", b, n);
    });
    ExpectGolden(goldens, &seen, "valet_off", TeslaBLE::CarServer::DisableValetMode);
    ExpectGolden(goldens, &seen, "guest_on", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetGuestMode(true, b, n);
    });
    ExpectGolden(goldens, &seen, "ping", TeslaBLE::CarServer::Ping);
    ExpectGolden(goldens, &seen, "software_update_60", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::ScheduleSoftwareUpdate(60, b, n);
    });
    ExpectGolden(goldens, &seen, "cancel_update", TeslaBLE::CarServer::CancelSoftwareUpdate);
    ExpectGolden(goldens, &seen, "homelink", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::TriggerHomelink(37.4f, -122.1f, b, n);
    });
    ExpectGolden(goldens, &seen, "name_kyoto", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetVehicleName("Kyoto", b, n);
    });
    ExpectGolden(goldens, &seen, "media_prev", TeslaBLE::CarServer::PreviousMediaTrack);
    ExpectGolden(goldens, &seen, "volume_down", TeslaBLE::CarServer::VolumeDown);
    ExpectGolden(goldens, &seen, "parental_on", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::ParentalControlsActivate("2468", b, n);
    });
    ExpectGolden(goldens, &seen, "low_power", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetLowPowerMode(true, b, n);
    });
    ExpectGolden(goldens, &seen, "accessory", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::SetKeepAccessoryPowerMode(true, b, n);
    });
    ExpectGolden(goldens, &seen, "pin_admin", TeslaBLE::CarServer::ClearPinToDriveAdmin);
    ExpectGolden(goldens, &seen, "parental_speed", [](unsigned char *b, size_t *n) {
        return TeslaBLE::CarServer::ParentalControlsSetSpeedLimit(65.0, b, n);
    });
    ExpectGolden(goldens, &seen, "add_charge_schedule", [](unsigned char *b, size_t *n) {
        CarServer_ChargeSchedule schedule = CarServer_ChargeSchedule_init_zero;
        schedule.id = 42;
        schedule.enabled = true;
        schedule.name[0] = 'h';
        schedule.name[1] = 'o';
        schedule.name[2] = 'm';
        schedule.name[3] = 'e';
        return TeslaBLE::CarServer::AddChargeSchedule(&schedule, b, n);
    });
    ExpectGolden(goldens, &seen, "lock", TeslaBLE::Security::Lock);
    ExpectGolden(goldens, &seen, "unlock", TeslaBLE::Security::Unlock);
    ExpectGolden(goldens, &seen, "wake", TeslaBLE::Security::Wake);
    ExpectGolden(goldens, &seen, "auto_secure", TeslaBLE::Security::AutoSecure);
    ExpectGolden(goldens, &seen, "remote_drive", TeslaBLE::Security::RemoteDrive);
    ExpectGolden(goldens, &seen, "open_trunk", TeslaBLE::Security::OpenTrunk);
    ExpectGolden(goldens, &seen, "close_trunk", TeslaBLE::Security::CloseTrunk);
    ExpectGolden(goldens, &seen, "open_frunk", TeslaBLE::Security::OpenFrunk);
    ExpectGolden(goldens, &seen, "open_tonneau", TeslaBLE::Security::OpenTonneau);
    ExpectGolden(goldens, &seen, "close_tonneau", TeslaBLE::Security::CloseTonneau);
    ExpectGolden(goldens, &seen, "stop_tonneau", TeslaBLE::Security::StopTonneau);
    ExpectGolden(goldens, &seen, "get_status", TeslaBLE::Security::GetStatus);
    ExpectGolden(goldens, &seen, "whitelist_info", TeslaBLE::Security::GetWhitelistInfo);
    ExpectGolden(goldens, &seen, "whitelist_entry_3", [](unsigned char *b, size_t *n) {
        return TeslaBLE::Security::GetWhitelistEntryInfo(3, b, n);
    });
    ExpectGolden(goldens, &seen, "remove_key", [](unsigned char *b, size_t *n) {
        return TeslaBLE::Security::RemoveKey(kTeslaTestPubkey, sizeof kTeslaTestPubkey, b, n);
    });
    REQUIRE(seen.size() == goldens.size());
}
