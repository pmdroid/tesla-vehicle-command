/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#ifndef TESLA_BLE_CARSERVER_H
#define TESLA_BLE_CARSERVER_H
#include <car_server.pb.h>
#include <shared.h>

namespace TeslaBLE {
    enum ClimateLevel {
        ClimateOff = 0,
        ClimateLow,
        ClimateMed,
        ClimateHigh,
    };

    enum ChargingPolicy {
        ChargingPolicyOff = 0,
        ChargingPolicyAllDays,
        ChargingPolicyWeekdays,
    };

    enum SeatPosition {
        SeatFrontLeft = 0,
        SeatFrontRight,
        SeatSecondRowLeft,
        SeatSecondRowLeftBack,
        SeatSecondRowCenter,
        SeatSecondRowRight,
        SeatSecondRowRightBack,
        SeatThirdRowLeft,
        SeatThirdRowRight,
    };

    enum VehicleDataCategory {
        VehicleDataCharge = 0,
        VehicleDataClimate,
        VehicleDataDrive,
        VehicleDataLocation,
        VehicleDataClosures,
        VehicleDataChargeSchedule,
        VehicleDataPreconditioningSchedule,
        VehicleDataTirePressure,
        VehicleDataMedia,
        VehicleDataMediaDetail,
        VehicleDataSoftwareUpdate,
        VehicleDataParentalControls,
    };

    class CarServer {
        static int BuildActionMessage(
            CarServer_Action *car_server_action, unsigned char *buffer, size_t *buffer_size);

        static int EncodeVehicleAction(const CarServer_VehicleAction &vehicle_action, unsigned char *buffer,
                                       size_t *buffer_size);

        static int ToggleClimate(bool status, unsigned char *buffer, size_t *buffer_size);

        static int EmptyVehicleAction(pb_size_t which, unsigned char *buffer, size_t *buffer_size);

        static int VolumeDelta(int32_t delta, unsigned char *buffer, size_t *buffer_size);

    public:
        static int TurnOnClimate(unsigned char *buffer, size_t *buffer_size);

        static int TurnOffClimate(unsigned char *buffer, size_t *buffer_size);

        static int NextMediaTrack(unsigned char *buffer, size_t *buffer_size);

        static int PlayMedia(unsigned char *buffer, size_t *buffer_size);

        static int SetVolume(float absolute, unsigned char *buffer, size_t *buffer_size);

        static int SetChargingLimit(int32_t percent, unsigned char *buffer, size_t *buffer_size);

        static int Vent(unsigned char *buffer, size_t *buffer_size);

        static int StartCharging(unsigned char *buffer, size_t *buffer_size);

        static int StopCharging(unsigned char *buffer, size_t *buffer_size);

        static int OpenChargePort(unsigned char *buffer, size_t *buffer_size);

        static int CloseChargePort(unsigned char *buffer, size_t *buffer_size);

        static int GetVehicleData(VehicleDataCategory category, unsigned char *buffer,
                                  size_t *buffer_size);

        static int ChangeClimateTemp(float driver_celsius, float passenger_celsius, unsigned char *buffer,
                                     size_t *buffer_size);

        static int SetSteeringWheelHeater(bool on, unsigned char *buffer, size_t *buffer_size);

        static int SetPreconditioningMax(bool on, bool manual_override, unsigned char *buffer,
                                         size_t *buffer_size);

        static int SetBioweaponDefenseMode(bool on, bool manual_override, unsigned char *buffer,
                                           size_t *buffer_size);

        static int SetCabinOverheatProtection(bool on, bool fan_only, unsigned char *buffer,
                                              size_t *buffer_size);

        static int SetCopTemp(CarServer_ClimateState_CopActivationTemp temp, unsigned char *buffer,
                              size_t *buffer_size);

        static int SetClimateKeeperMode(CarServer_HvacClimateKeeperAction_ClimateKeeperAction_E mode,
                                        bool manual_override, unsigned char *buffer, size_t *buffer_size);

        static int SetSeatHeater(SeatPosition seat, ClimateLevel level, unsigned char *buffer,
                                 size_t *buffer_size);

        static int SetSeatCooler(SeatPosition seat, ClimateLevel level, unsigned char *buffer,
                                 size_t *buffer_size);

        static int AutoSeatClimate(SeatPosition seat, bool on, unsigned char *buffer, size_t *buffer_size);

        static int SetChargingAmps(int32_t amps, unsigned char *buffer, size_t *buffer_size);

        static int ChargeMaxRange(unsigned char *buffer, size_t *buffer_size);

        static int ChargeStandardRange(unsigned char *buffer, size_t *buffer_size);

        static int ScheduleCharging(bool enabled, int32_t minutes_from_midnight, unsigned char *buffer,
                                    size_t *buffer_size);

        static int ScheduleDeparture(int32_t departure_minutes, int32_t off_peak_end_minutes,
                                     ChargingPolicy preconditioning, ChargingPolicy off_peak,
                                     unsigned char *buffer, size_t *buffer_size);

        static int ClearScheduledDeparture(unsigned char *buffer, size_t *buffer_size);

        static int GetNearbyCharging(unsigned char *buffer, size_t *buffer_size);

        static int HonkHorn(unsigned char *buffer, size_t *buffer_size);

        static int FlashLights(unsigned char *buffer, size_t *buffer_size);

        static int CloseWindows(unsigned char *buffer, size_t *buffer_size);

        static int SetSunroofLevel(int32_t absolute_level, unsigned char *buffer, size_t *buffer_size);

        static int SetSentryMode(bool on, unsigned char *buffer, size_t *buffer_size);

        static int EnableValetMode(const char *pin, unsigned char *buffer, size_t *buffer_size);

        static int DisableValetMode(unsigned char *buffer, size_t *buffer_size);

        static int ResetValetPin(unsigned char *buffer, size_t *buffer_size);

        static int SetGuestMode(bool on, unsigned char *buffer, size_t *buffer_size);

        static int EraseGuestData(unsigned char *buffer, size_t *buffer_size);

        static int Ping(unsigned char *buffer, size_t *buffer_size);

        static int ScheduleSoftwareUpdate(int32_t offset_sec, unsigned char *buffer, size_t *buffer_size);

        static int CancelSoftwareUpdate(unsigned char *buffer, size_t *buffer_size);

        static int TriggerHomelink(float latitude, float longitude, unsigned char *buffer, size_t *buffer_size);

        static int SetVehicleName(const char *name, unsigned char *buffer, size_t *buffer_size);

        static int PreviousMediaTrack(unsigned char *buffer, size_t *buffer_size);

        static int NextMediaFavorite(unsigned char *buffer, size_t *buffer_size);

        static int PreviousMediaFavorite(unsigned char *buffer, size_t *buffer_size);

        static int VolumeUp(unsigned char *buffer, size_t *buffer_size);

        static int VolumeDown(unsigned char *buffer, size_t *buffer_size);
    };
} // TeslaBLE

#endif //TESLA_BLE_CARSERVER_H
