#include "carserver.h"

#include <cstdio>
#include <cstring>

#include <car_server.pb.h>

#include <pb.h>
#include <pb_encode.h>

namespace TeslaBLE {
    int CarServer::BuildActionMessage(CarServer_Action *car_server_action, unsigned char *buffer,
                                      size_t *buffer_size) {
        pb_ostream_t size_stream = {nullptr};
        if (!pb_encode(&size_stream, CarServer_Action_fields, car_server_action)) {
            printf("Failed to encode message: %s", PB_GET_ERROR(&size_stream));
            return ResultCode::NANOPB_ENCODE_ERROR;
        }

        pb_ostream_t stream = pb_ostream_from_buffer(buffer, size_stream.bytes_written);
        if (!pb_encode(&stream, CarServer_Action_fields, car_server_action)) {
            printf("Failed to encode message: %s", PB_GET_ERROR(&stream));
            return ResultCode::NANOPB_ENCODE_ERROR;
        }

        *buffer_size = stream.bytes_written;
        return ResultCode::SUCCESS;
    }

    int CarServer::EncodeVehicleAction(const CarServer_VehicleAction &vehicle_action, unsigned char *buffer,
                                       size_t *buffer_size) {
        CarServer_Action car_server_action = CarServer_Action_init_zero;
        car_server_action.which_action_msg = CarServer_Action_vehicleAction_tag;
        car_server_action.action_msg.vehicleAction = vehicle_action;
        return CarServer::BuildActionMessage(&car_server_action, buffer, buffer_size);
    }

    int CarServer::StartCharging(unsigned char *buffer, size_t *buffer_size) {
        CarServer_ChargingStartStopAction start_stop_charging = CarServer_ChargingStartStopAction_init_default;
        start_stop_charging.charging_action.start.dummy_field = 1;
        start_stop_charging.which_charging_action = CarServer_ChargingStartStopAction_start_tag;

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_chargingStartStopAction_tag;
        vehicle_action.vehicle_action_msg.chargingStartStopAction = start_stop_charging;

        CarServer_Action car_server_action = CarServer_Action_init_default;
        car_server_action.action_msg.vehicleAction = vehicle_action;
        car_server_action.which_action_msg = CarServer_Action_vehicleAction_tag;

        return CarServer::BuildActionMessage(&car_server_action, buffer, buffer_size);
    }

    int CarServer::StopCharging(unsigned char *buffer, size_t *buffer_size) {
        CarServer_ChargingStartStopAction start_stop_charging = CarServer_ChargingStartStopAction_init_default;
        start_stop_charging.charging_action.stop.dummy_field = 1;
        start_stop_charging.which_charging_action = CarServer_ChargingStartStopAction_stop_tag;

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_chargingStartStopAction_tag;
        vehicle_action.vehicle_action_msg.chargingStartStopAction = start_stop_charging;

        CarServer_Action car_server_action = CarServer_Action_init_default;
        car_server_action.action_msg.vehicleAction = vehicle_action;
        car_server_action.which_action_msg = CarServer_Action_vehicleAction_tag;

        return CarServer::BuildActionMessage(&car_server_action, buffer, buffer_size);
    }

    int CarServer::OpenChargePort(unsigned char *buffer, size_t *buffer_size) {
        CarServer_ChargePortDoorOpen open_chargeport = CarServer_ChargePortDoorOpen_init_default;
        open_chargeport.dummy_field = 1;

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_chargePortDoorOpen_tag;
        vehicle_action.vehicle_action_msg.chargePortDoorOpen = open_chargeport;

        CarServer_Action car_server_action = CarServer_Action_init_default;
        car_server_action.action_msg.vehicleAction = vehicle_action;
        car_server_action.which_action_msg = CarServer_Action_vehicleAction_tag;

        return CarServer::BuildActionMessage(&car_server_action, buffer, buffer_size);
    }

    int CarServer::CloseChargePort(unsigned char *buffer, size_t *buffer_size) {
        CarServer_ChargePortDoorClose close_chargeport = CarServer_ChargePortDoorClose_init_default;
        close_chargeport.dummy_field = 1;

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_chargePortDoorClose_tag;
        vehicle_action.vehicle_action_msg.chargePortDoorClose = close_chargeport;

        CarServer_Action car_server_action = CarServer_Action_init_default;
        car_server_action.action_msg.vehicleAction = vehicle_action;
        car_server_action.which_action_msg = CarServer_Action_vehicleAction_tag;

        return CarServer::BuildActionMessage(&car_server_action, buffer, buffer_size);
    }

    int CarServer::ToggleClimate(bool status, unsigned char *buffer, size_t *buffer_size) {
        CarServer_HvacAutoAction hvac_auto_action = CarServer_HvacAutoAction_init_default;
        hvac_auto_action.power_on = status;

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_hvacAutoAction_tag;
        vehicle_action.vehicle_action_msg.hvacAutoAction = hvac_auto_action;

        CarServer_Action car_server_action = CarServer_Action_init_default;
        car_server_action.action_msg.vehicleAction = vehicle_action;
        car_server_action.which_action_msg = CarServer_Action_vehicleAction_tag;

        return CarServer::BuildActionMessage(&car_server_action, buffer, buffer_size);
    }


    int CarServer::TurnOnClimate(unsigned char *buffer, size_t *buffer_size) {
        return CarServer::ToggleClimate(true, buffer, buffer_size);
    }

    int CarServer::TurnOffClimate(unsigned char *buffer, size_t *buffer_size) {
        return CarServer::ToggleClimate(false, buffer, buffer_size);
    }

    int CarServer::NextMediaTrack(unsigned char *buffer, size_t *buffer_size) {
        CarServer_MediaNextTrack media_next_track = CarServer_MediaNextTrack_init_default;
        media_next_track.dummy_field = 1;

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_mediaNextTrack_tag;
        vehicle_action.vehicle_action_msg.mediaNextTrack = media_next_track;

        CarServer_Action car_server_action = CarServer_Action_init_default;
        car_server_action.action_msg.vehicleAction = vehicle_action;
        car_server_action.which_action_msg = CarServer_Action_vehicleAction_tag;

        return CarServer::BuildActionMessage(&car_server_action, buffer, buffer_size);
    }

    int CarServer::PlayMedia(unsigned char *buffer, size_t *buffer_size) {
        CarServer_MediaPlayAction play_action = CarServer_MediaPlayAction_init_default;
        play_action.dummy_field = 1;

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_mediaPlayAction_tag;
        vehicle_action.vehicle_action_msg.mediaPlayAction = play_action;

        CarServer_Action car_server_action = CarServer_Action_init_default;
        car_server_action.action_msg.vehicleAction = vehicle_action;
        car_server_action.which_action_msg = CarServer_Action_vehicleAction_tag;

        return CarServer::BuildActionMessage(&car_server_action, buffer, buffer_size);
    }

    int CarServer::SetVolume(float absolute, unsigned char *buffer, size_t *buffer_size) {
        CarServer_MediaUpdateVolume update_volume = CarServer_MediaUpdateVolume_init_default;
        update_volume.media_volume.volume_absolute_float = absolute;
        update_volume.which_media_volume = CarServer_MediaUpdateVolume_volume_absolute_float_tag;

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_mediaUpdateVolume_tag;
        vehicle_action.vehicle_action_msg.mediaUpdateVolume = update_volume;

        CarServer_Action car_server_action = CarServer_Action_init_default;
        car_server_action.action_msg.vehicleAction = vehicle_action;
        car_server_action.which_action_msg = CarServer_Action_vehicleAction_tag;

        return CarServer::BuildActionMessage(&car_server_action, buffer, buffer_size);
    }

    int CarServer::SetChargingLimit(int32_t percent, unsigned char *buffer, size_t *buffer_size) {
        CarServer_ChargingSetLimitAction set_charging_limit_action = CarServer_ChargingSetLimitAction_init_default;
        set_charging_limit_action.percent = percent;

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_chargingSetLimitAction_tag;
        vehicle_action.vehicle_action_msg.chargingSetLimitAction = set_charging_limit_action;

        CarServer_Action car_server_action = CarServer_Action_init_default;
        car_server_action.action_msg.vehicleAction = vehicle_action;
        car_server_action.which_action_msg = CarServer_Action_vehicleAction_tag;

        return CarServer::BuildActionMessage(&car_server_action, buffer, buffer_size);
    }

    int CarServer::Vent(unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleControlWindowAction window_action = CarServer_VehicleControlWindowAction_init_default;
        window_action.action.vent.dummy_field = 1;
        window_action.which_action = CarServer_VehicleControlWindowAction_vent_tag;

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_vehicleControlWindowAction_tag;
        vehicle_action.vehicle_action_msg.vehicleControlWindowAction = window_action;

        CarServer_Action car_server_action = CarServer_Action_init_default;
        car_server_action.action_msg.vehicleAction = vehicle_action;
        car_server_action.which_action_msg = CarServer_Action_vehicleAction_tag;

        return CarServer::BuildActionMessage(&car_server_action, buffer, buffer_size);
    }

    int CarServer::GetVehicleData(VehicleDataCategory category, unsigned char *buffer,
                                  size_t *buffer_size) {
        CarServer_GetVehicleData get_vehicle_data = CarServer_GetVehicleData_init_zero;
        switch (category) {
            case VehicleDataCharge:
                get_vehicle_data.has_getChargeState = true;
                break;
            case VehicleDataClimate:
                get_vehicle_data.has_getClimateState = true;
                break;
            case VehicleDataDrive:
                get_vehicle_data.has_getDriveState = true;
                break;
            case VehicleDataLocation:
                get_vehicle_data.has_getLocationState = true;
                break;
            case VehicleDataClosures:
                get_vehicle_data.has_getClosuresState = true;
                break;
            case VehicleDataChargeSchedule:
                get_vehicle_data.has_getChargeScheduleState = true;
                break;
            case VehicleDataPreconditioningSchedule:
                get_vehicle_data.has_getPreconditioningScheduleState = true;
                break;
            case VehicleDataTirePressure:
                get_vehicle_data.has_getTirePressureState = true;
                break;
            case VehicleDataMedia:
                get_vehicle_data.has_getMediaState = true;
                break;
            case VehicleDataMediaDetail:
                get_vehicle_data.has_getMediaDetailState = true;
                break;
            case VehicleDataSoftwareUpdate:
                get_vehicle_data.has_getSoftwareUpdateState = true;
                break;
            case VehicleDataParentalControls:
                get_vehicle_data.has_getParentalControlsState = true;
                break;
            default:
                return ResultCode::ERROR;
        }

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_getVehicleData_tag;
        vehicle_action.vehicle_action_msg.getVehicleData = get_vehicle_data;

        CarServer_Action car_server_action = CarServer_Action_init_zero;
        car_server_action.which_action_msg = CarServer_Action_vehicleAction_tag;
        car_server_action.action_msg.vehicleAction = vehicle_action;

        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::ChangeClimateTemp(float driver_celsius, float passenger_celsius, unsigned char *buffer,
                                     size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_hvacTemperatureAdjustmentAction_tag;
        vehicle_action.vehicle_action_msg.hvacTemperatureAdjustmentAction.driver_temp_celsius = driver_celsius;
        vehicle_action.vehicle_action_msg.hvacTemperatureAdjustmentAction.passenger_temp_celsius = passenger_celsius;
        vehicle_action.vehicle_action_msg.hvacTemperatureAdjustmentAction.has_level = true;
        vehicle_action.vehicle_action_msg.hvacTemperatureAdjustmentAction.level.which_type =
            CarServer_HvacTemperatureAdjustmentAction_Temperature_TEMP_MAX_tag;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::SetSteeringWheelHeater(bool on, unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_hvacSteeringWheelHeaterAction_tag;
        vehicle_action.vehicle_action_msg.hvacSteeringWheelHeaterAction.power_on = on;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::SetPreconditioningMax(bool on, bool manual_override, unsigned char *buffer,
                                         size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_hvacSetPreconditioningMaxAction_tag;
        vehicle_action.vehicle_action_msg.hvacSetPreconditioningMaxAction.on = on;
        vehicle_action.vehicle_action_msg.hvacSetPreconditioningMaxAction.manual_override = manual_override;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::SetBioweaponDefenseMode(bool on, bool manual_override, unsigned char *buffer,
                                           size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_hvacBioweaponModeAction_tag;
        vehicle_action.vehicle_action_msg.hvacBioweaponModeAction.on = on;
        vehicle_action.vehicle_action_msg.hvacBioweaponModeAction.manual_override = manual_override;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::SetCabinOverheatProtection(bool on, bool fan_only, unsigned char *buffer,
                                              size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_setCabinOverheatProtectionAction_tag;
        vehicle_action.vehicle_action_msg.setCabinOverheatProtectionAction.on = on;
        vehicle_action.vehicle_action_msg.setCabinOverheatProtectionAction.fan_only = fan_only;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::SetCopTemp(CarServer_ClimateState_CopActivationTemp temp, unsigned char *buffer,
                              size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_setCopTempAction_tag;
        vehicle_action.vehicle_action_msg.setCopTempAction.copActivationTemp = temp;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::SetClimateKeeperMode(CarServer_HvacClimateKeeperAction_ClimateKeeperAction_E mode,
                                        bool manual_override, unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_hvacClimateKeeperAction_tag;
        vehicle_action.vehicle_action_msg.hvacClimateKeeperAction.ClimateKeeperAction = mode;
        vehicle_action.vehicle_action_msg.hvacClimateKeeperAction.manual_override = manual_override;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    static pb_size_t SeatHeaterLevelTag(ClimateLevel level) {
        switch (level) {
            case ClimateOff:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_SEAT_HEATER_OFF_tag;
            case ClimateLow:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_SEAT_HEATER_LOW_tag;
            case ClimateMed:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_SEAT_HEATER_MED_tag;
            case ClimateHigh:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_SEAT_HEATER_HIGH_tag;
            default:
                return 0;
        }
    }

    static pb_size_t SeatHeaterPositionTag(SeatPosition seat) {
        switch (seat) {
            case SeatFrontLeft:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_CAR_SEAT_FRONT_LEFT_tag;
            case SeatFrontRight:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_CAR_SEAT_FRONT_RIGHT_tag;
            case SeatSecondRowLeft:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_CAR_SEAT_REAR_LEFT_tag;
            case SeatSecondRowLeftBack:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_CAR_SEAT_REAR_LEFT_BACK_tag;
            case SeatSecondRowCenter:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_CAR_SEAT_REAR_CENTER_tag;
            case SeatSecondRowRight:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_CAR_SEAT_REAR_RIGHT_tag;
            case SeatSecondRowRightBack:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_CAR_SEAT_REAR_RIGHT_BACK_tag;
            case SeatThirdRowLeft:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_CAR_SEAT_THIRD_ROW_LEFT_tag;
            case SeatThirdRowRight:
                return CarServer_HvacSeatHeaterActions_HvacSeatHeaterAction_CAR_SEAT_THIRD_ROW_RIGHT_tag;
            default:
                return 0;
        }
    }

    int CarServer::SetSeatHeater(SeatPosition seat, ClimateLevel level, unsigned char *buffer,
                                 size_t *buffer_size) {
        const pb_size_t level_tag = SeatHeaterLevelTag(level);
        const pb_size_t seat_tag = SeatHeaterPositionTag(seat);
        if (level_tag == 0 || seat_tag == 0) {
            return ResultCode::ERROR;
        }

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_hvacSeatHeaterActions_tag;
        auto &actions = vehicle_action.vehicle_action_msg.hvacSeatHeaterActions;
        actions.hvacSeatHeaterAction_count = 1;
        actions.hvacSeatHeaterAction[0].which_seat_heater_level = level_tag;
        actions.hvacSeatHeaterAction[0].which_seat_position = seat_tag;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::SetSeatCooler(SeatPosition seat, ClimateLevel level, unsigned char *buffer,
                                 size_t *buffer_size) {
        CarServer_HvacSeatCoolerActions_HvacSeatCoolerPosition_E proto_seat;
        switch (seat) {
            case SeatFrontLeft:
                proto_seat = CarServer_HvacSeatCoolerActions_HvacSeatCoolerPosition_E_HvacSeatCoolerPosition_FrontLeft;
                break;
            case SeatFrontRight:
                proto_seat =
                    CarServer_HvacSeatCoolerActions_HvacSeatCoolerPosition_E_HvacSeatCoolerPosition_FrontRight;
                break;
            default:
                return ResultCode::ERROR;
        }

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_hvacSeatCoolerActions_tag;
        auto &actions = vehicle_action.vehicle_action_msg.hvacSeatCoolerActions;
        actions.hvacSeatCoolerAction_count = 1;
        actions.hvacSeatCoolerAction[0].seat_position = proto_seat;
        actions.hvacSeatCoolerAction[0].seat_cooler_level =
            static_cast<CarServer_HvacSeatCoolerActions_HvacSeatCoolerLevel_E>(level + 1);
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::AutoSeatClimate(SeatPosition seat, bool on, unsigned char *buffer, size_t *buffer_size) {
        CarServer_AutoSeatClimateAction_AutoSeatPosition_E proto_seat;
        switch (seat) {
            case SeatFrontLeft:
                proto_seat = CarServer_AutoSeatClimateAction_AutoSeatPosition_E_AutoSeatPosition_FrontLeft;
                break;
            case SeatFrontRight:
                proto_seat = CarServer_AutoSeatClimateAction_AutoSeatPosition_E_AutoSeatPosition_FrontRight;
                break;
            default:
                return ResultCode::ERROR;
        }

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_autoSeatClimateAction_tag;
        auto &action = vehicle_action.vehicle_action_msg.autoSeatClimateAction;
        action.carseat_count = 1;
        action.carseat[0].on = on;
        action.carseat[0].seat_position = proto_seat;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::SetChargingAmps(int32_t amps, unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_setChargingAmpsAction_tag;
        vehicle_action.vehicle_action_msg.setChargingAmpsAction.charging_amps = amps;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::ChargeMaxRange(unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_chargingStartStopAction_tag;
        vehicle_action.vehicle_action_msg.chargingStartStopAction.which_charging_action =
            CarServer_ChargingStartStopAction_start_max_range_tag;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::ChargeStandardRange(unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_chargingStartStopAction_tag;
        vehicle_action.vehicle_action_msg.chargingStartStopAction.which_charging_action =
            CarServer_ChargingStartStopAction_start_standard_tag;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::ScheduleCharging(bool enabled, int32_t minutes_from_midnight, unsigned char *buffer,
                                    size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_scheduledChargingAction_tag;
        vehicle_action.vehicle_action_msg.scheduledChargingAction.enabled = enabled;
        vehicle_action.vehicle_action_msg.scheduledChargingAction.charging_time = minutes_from_midnight;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    static bool FillTimes(ChargingPolicy policy, pb_size_t *which, pb_size_t all_week_tag, pb_size_t weekdays_tag) {
        switch (policy) {
            case ChargingPolicyOff:
                return false;
            case ChargingPolicyAllDays:
                *which = all_week_tag;
                return true;
            case ChargingPolicyWeekdays:
                *which = weekdays_tag;
                return true;
            default:
                return false;
        }
    }

    int CarServer::ScheduleDeparture(int32_t departure_minutes, int32_t off_peak_end_minutes,
                                     ChargingPolicy preconditioning, ChargingPolicy off_peak,
                                     unsigned char *buffer, size_t *buffer_size) {
        if (departure_minutes < 0 || departure_minutes > 24 * 60) {
            return ResultCode::ERROR;
        }

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_scheduledDepartureAction_tag;
        auto &dep = vehicle_action.vehicle_action_msg.scheduledDepartureAction;
        dep.enabled = true;
        dep.departure_time = departure_minutes;
        dep.off_peak_hours_end_time = off_peak_end_minutes;
        dep.has_preconditioning_times =
            FillTimes(preconditioning, &dep.preconditioning_times.which_times,
                      CarServer_PreconditioningTimes_all_week_tag, CarServer_PreconditioningTimes_weekdays_tag);
        dep.has_off_peak_charging_times =
            FillTimes(off_peak, &dep.off_peak_charging_times.which_times,
                      CarServer_OffPeakChargingTimes_all_week_tag, CarServer_OffPeakChargingTimes_weekdays_tag);
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::ClearScheduledDeparture(unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_scheduledDepartureAction_tag;
        vehicle_action.vehicle_action_msg.scheduledDepartureAction.enabled = false;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::GetNearbyCharging(unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_getNearbyChargingSites_tag;
        vehicle_action.vehicle_action_msg.getNearbyChargingSites.include_meta_data = true;
        vehicle_action.vehicle_action_msg.getNearbyChargingSites.radius = 200;
        vehicle_action.vehicle_action_msg.getNearbyChargingSites.count = 10;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::EmptyVehicleAction(pb_size_t which, unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = which;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    static bool FourDigitPin(const char *pin) {
        if (pin == nullptr) {
            return false;
        }
        size_t n = 0;
        while (pin[n] != '\0') {
            if (pin[n] < '0' || pin[n] > '9') {
                return false;
            }
            ++n;
        }
        return n == 4;
    }

    int CarServer::HonkHorn(unsigned char *buffer, size_t *buffer_size) {
        return CarServer::EmptyVehicleAction(CarServer_VehicleAction_vehicleControlHonkHornAction_tag, buffer,
                                             buffer_size);
    }

    int CarServer::FlashLights(unsigned char *buffer, size_t *buffer_size) {
        return CarServer::EmptyVehicleAction(CarServer_VehicleAction_vehicleControlFlashLightsAction_tag, buffer,
                                             buffer_size);
    }

    int CarServer::CloseWindows(unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_vehicleControlWindowAction_tag;
        vehicle_action.vehicle_action_msg.vehicleControlWindowAction.which_action =
            CarServer_VehicleControlWindowAction_close_tag;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::SetSunroofLevel(int32_t absolute_level, unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_vehicleControlSunroofOpenCloseAction_tag;
        vehicle_action.vehicle_action_msg.vehicleControlSunroofOpenCloseAction.which_sunroof_level =
            CarServer_VehicleControlSunroofOpenCloseAction_absolute_level_tag;
        vehicle_action.vehicle_action_msg.vehicleControlSunroofOpenCloseAction.sunroof_level.absolute_level =
            absolute_level;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::SetSentryMode(bool on, unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_vehicleControlSetSentryModeAction_tag;
        vehicle_action.vehicle_action_msg.vehicleControlSetSentryModeAction.on = on;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::EnableValetMode(const char *pin, unsigned char *buffer, size_t *buffer_size) {
        if (!FourDigitPin(pin)) {
            return ResultCode::ERROR;
        }
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_vehicleControlSetValetModeAction_tag;
        vehicle_action.vehicle_action_msg.vehicleControlSetValetModeAction.on = true;
        strncpy(vehicle_action.vehicle_action_msg.vehicleControlSetValetModeAction.password, pin,
                sizeof(vehicle_action.vehicle_action_msg.vehicleControlSetValetModeAction.password) - 1);
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::DisableValetMode(unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_vehicleControlSetValetModeAction_tag;
        vehicle_action.vehicle_action_msg.vehicleControlSetValetModeAction.on = false;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::ResetValetPin(unsigned char *buffer, size_t *buffer_size) {
        return CarServer::EmptyVehicleAction(CarServer_VehicleAction_vehicleControlResetValetPinAction_tag, buffer,
                                             buffer_size);
    }

    int CarServer::SetGuestMode(bool on, unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_guestModeAction_tag;
        vehicle_action.vehicle_action_msg.guestModeAction.GuestModeActive = on;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::EraseGuestData(unsigned char *buffer, size_t *buffer_size) {
        return CarServer::EmptyVehicleAction(CarServer_VehicleAction_eraseUserDataAction_tag, buffer, buffer_size);
    }

    int CarServer::Ping(unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_ping_tag;
        vehicle_action.vehicle_action_msg.ping.ping_id = 1;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::ScheduleSoftwareUpdate(int32_t offset_sec, unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg =
            CarServer_VehicleAction_vehicleControlScheduleSoftwareUpdateAction_tag;
        vehicle_action.vehicle_action_msg.vehicleControlScheduleSoftwareUpdateAction.offset_sec = offset_sec;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::CancelSoftwareUpdate(unsigned char *buffer, size_t *buffer_size) {
        return CarServer::EmptyVehicleAction(CarServer_VehicleAction_vehicleControlCancelSoftwareUpdateAction_tag,
                                             buffer, buffer_size);
    }

    int CarServer::TriggerHomelink(float latitude, float longitude, unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_vehicleControlTriggerHomelinkAction_tag;
        vehicle_action.vehicle_action_msg.vehicleControlTriggerHomelinkAction.has_location = true;
        vehicle_action.vehicle_action_msg.vehicleControlTriggerHomelinkAction.location.latitude = latitude;
        vehicle_action.vehicle_action_msg.vehicleControlTriggerHomelinkAction.location.longitude = longitude;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::SetVehicleName(const char *name, unsigned char *buffer, size_t *buffer_size) {
        if (name == nullptr || name[0] == '\0') {
            return ResultCode::ERROR;
        }
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_setVehicleNameAction_tag;
        strncpy(vehicle_action.vehicle_action_msg.setVehicleNameAction.vehicleName, name,
                sizeof(vehicle_action.vehicle_action_msg.setVehicleNameAction.vehicleName) - 1);
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::PreviousMediaTrack(unsigned char *buffer, size_t *buffer_size) {
        return CarServer::EmptyVehicleAction(CarServer_VehicleAction_mediaPreviousTrack_tag, buffer, buffer_size);
    }

    int CarServer::NextMediaFavorite(unsigned char *buffer, size_t *buffer_size) {
        return CarServer::EmptyVehicleAction(CarServer_VehicleAction_mediaNextFavorite_tag, buffer, buffer_size);
    }

    int CarServer::PreviousMediaFavorite(unsigned char *buffer, size_t *buffer_size) {
        return CarServer::EmptyVehicleAction(CarServer_VehicleAction_mediaPreviousFavorite_tag, buffer, buffer_size);
    }

    int CarServer::VolumeDelta(int32_t delta, unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_mediaUpdateVolume_tag;
        vehicle_action.vehicle_action_msg.mediaUpdateVolume.which_media_volume =
            CarServer_MediaUpdateVolume_volume_delta_tag;
        vehicle_action.vehicle_action_msg.mediaUpdateVolume.media_volume.volume_delta = delta;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::VolumeUp(unsigned char *buffer, size_t *buffer_size) {
        return CarServer::VolumeDelta(1, buffer, buffer_size);
    }

    int CarServer::VolumeDown(unsigned char *buffer, size_t *buffer_size) {
        return CarServer::VolumeDelta(-1, buffer, buffer_size);
    }

    int CarServer::AddChargeSchedule(const CarServer_ChargeSchedule *schedule, unsigned char *buffer,
                                     size_t *buffer_size) {
        if (schedule == nullptr) {
            return ResultCode::ERROR;
        }
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_addChargeScheduleAction_tag;
        vehicle_action.vehicle_action_msg.addChargeScheduleAction = *schedule;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::RemoveChargeSchedule(uint64_t id, unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_removeChargeScheduleAction_tag;
        vehicle_action.vehicle_action_msg.removeChargeScheduleAction.id = id;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::BatchRemoveChargeSchedules(bool home, bool work, bool other, unsigned char *buffer,
                                              size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_batchRemoveChargeSchedulesAction_tag;
        vehicle_action.vehicle_action_msg.batchRemoveChargeSchedulesAction.home = home;
        vehicle_action.vehicle_action_msg.batchRemoveChargeSchedulesAction.work = work;
        vehicle_action.vehicle_action_msg.batchRemoveChargeSchedulesAction.other = other;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::AddPreconditionSchedule(const CarServer_PreconditionSchedule *schedule, unsigned char *buffer,
                                           size_t *buffer_size) {
        if (schedule == nullptr) {
            return ResultCode::ERROR;
        }
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_addPreconditionScheduleAction_tag;
        vehicle_action.vehicle_action_msg.addPreconditionScheduleAction = *schedule;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::RemovePreconditionSchedule(uint64_t id, unsigned char *buffer, size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_removePreconditionScheduleAction_tag;
        vehicle_action.vehicle_action_msg.removePreconditionScheduleAction.id = id;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }

    int CarServer::BatchRemovePreconditionSchedules(bool home, bool work, bool other, unsigned char *buffer,
                                                    size_t *buffer_size) {
        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_zero;
        vehicle_action.which_vehicle_action_msg =
            CarServer_VehicleAction_batchRemovePreconditionSchedulesAction_tag;
        vehicle_action.vehicle_action_msg.batchRemovePreconditionSchedulesAction.home = home;
        vehicle_action.vehicle_action_msg.batchRemovePreconditionSchedulesAction.work = work;
        vehicle_action.vehicle_action_msg.batchRemovePreconditionSchedulesAction.other = other;
        return CarServer::EncodeVehicleAction(vehicle_action, buffer, buffer_size);
    }
} // TeslaBLE


