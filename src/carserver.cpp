#include "carserver.h"

#include <cstdio>

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
        start_stop_charging.which_charging_action = CarServer_ChargingStartStopAction_start_tag;

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
} // TeslaBLE
