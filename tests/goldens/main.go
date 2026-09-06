package main

import (
	"fmt"
	"os"

	"google.golang.org/protobuf/proto"

	carserver "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/carserver"
	"github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/vcsec"
)

func dump(name string, m proto.Message) {
	b, err := proto.Marshal(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		os.Exit(1)
	}
	fmt.Printf("%s %x\n", name, b)
}

func car(va *carserver.VehicleAction) proto.Message {
	return &carserver.Action{
		ActionMsg: &carserver.Action_VehicleAction{VehicleAction: va},
	}
}

func main() {
	dump("climate_on", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_HvacAutoAction{
			HvacAutoAction: &carserver.HvacAutoAction{PowerOn: true},
		},
	}))
	dump("climate_off", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_HvacAutoAction{
			HvacAutoAction: &carserver.HvacAutoAction{PowerOn: false},
		},
	}))
	dump("climate_temp", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_HvacTemperatureAdjustmentAction{
			HvacTemperatureAdjustmentAction: &carserver.HvacTemperatureAdjustmentAction{
				DriverTempCelsius:    21.5,
				PassengerTempCelsius: 22.0,
				Level: &carserver.HvacTemperatureAdjustmentAction_Temperature{
					Type: &carserver.HvacTemperatureAdjustmentAction_Temperature_TEMP_MAX{},
				},
			},
		},
	}))
	dump("steering_wheel", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_HvacSteeringWheelHeaterAction{
			HvacSteeringWheelHeaterAction: &carserver.HvacSteeringWheelHeaterAction{PowerOn: true},
		},
	}))
	dump("seat_heater_fl_high", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_HvacSeatHeaterActions{
			HvacSeatHeaterActions: &carserver.HvacSeatHeaterActions{
				HvacSeatHeaterAction: []*carserver.HvacSeatHeaterActions_HvacSeatHeaterAction{{
					SeatHeaterLevel: &carserver.HvacSeatHeaterActions_HvacSeatHeaterAction_SEAT_HEATER_HIGH{},
					SeatPosition:    &carserver.HvacSeatHeaterActions_HvacSeatHeaterAction_CAR_SEAT_FRONT_LEFT{},
				}},
			},
		},
	}))
	dump("seat_cooler_fr_low", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_HvacSeatCoolerActions{
			HvacSeatCoolerActions: &carserver.HvacSeatCoolerActions{
				HvacSeatCoolerAction: []*carserver.HvacSeatCoolerActions_HvacSeatCoolerAction{{
					SeatCoolerLevel: carserver.HvacSeatCoolerActions_HvacSeatCoolerLevel_Low,
					SeatPosition:    carserver.HvacSeatCoolerActions_HvacSeatCoolerPosition_FrontRight,
				}},
			},
		},
	}))
	dump("climate_keeper_dog", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_HvacClimateKeeperAction{
			HvacClimateKeeperAction: &carserver.HvacClimateKeeperAction{
				ClimateKeeperAction: carserver.HvacClimateKeeperAction_ClimateKeeperAction_Dog,
				ManualOverride:      true,
			},
		},
	}))
	dump("bioweapon", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_HvacBioweaponModeAction{
			HvacBioweaponModeAction: &carserver.HvacBioweaponModeAction{On: true, ManualOverride: false},
		},
	}))
	dump("cop_fan", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_SetCabinOverheatProtectionAction{
			SetCabinOverheatProtectionAction: &carserver.SetCabinOverheatProtectionAction{On: true, FanOnly: true},
		},
	}))
	dump("cop_temp_high", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_SetCopTempAction{
			SetCopTempAction: &carserver.SetCopTempAction{
				CopActivationTemp: carserver.ClimateState_CopActivationTempHigh,
			},
		},
	}))
	dump("precondition_max", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_HvacSetPreconditioningMaxAction{
			HvacSetPreconditioningMaxAction: &carserver.HvacSetPreconditioningMaxAction{On: true, ManualOverride: true},
		},
	}))
	dump("auto_seat_fl", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_AutoSeatClimateAction{
			AutoSeatClimateAction: &carserver.AutoSeatClimateAction{
				Carseat: []*carserver.AutoSeatClimateAction_CarSeat{{
					On:           true,
					SeatPosition: carserver.AutoSeatClimateAction_AutoSeatPosition_FrontLeft,
				}},
			},
		},
	}))
	dump("charge_start", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_ChargingStartStopAction{
			ChargingStartStopAction: &carserver.ChargingStartStopAction{
				ChargingAction: &carserver.ChargingStartStopAction_Start{Start: &carserver.Void{}},
			},
		},
	}))
	dump("charge_stop", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_ChargingStartStopAction{
			ChargingStartStopAction: &carserver.ChargingStartStopAction{
				ChargingAction: &carserver.ChargingStartStopAction_Stop{Stop: &carserver.Void{}},
			},
		},
	}))
	dump("charge_limit_80", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_ChargingSetLimitAction{
			ChargingSetLimitAction: &carserver.ChargingSetLimitAction{Percent: 80},
		},
	}))
	dump("charge_amps_32", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_SetChargingAmpsAction{
			SetChargingAmpsAction: &carserver.SetChargingAmpsAction{ChargingAmps: 32},
		},
	}))
	dump("charge_max", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_ChargingStartStopAction{
			ChargingStartStopAction: &carserver.ChargingStartStopAction{
				ChargingAction: &carserver.ChargingStartStopAction_StartMaxRange{StartMaxRange: &carserver.Void{}},
			},
		},
	}))
	dump("charge_std", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_ChargingStartStopAction{
			ChargingStartStopAction: &carserver.ChargingStartStopAction{
				ChargingAction: &carserver.ChargingStartStopAction_StartStandard{StartStandard: &carserver.Void{}},
			},
		},
	}))
	dump("charge_port_open", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_ChargePortDoorOpen{
			ChargePortDoorOpen: &carserver.ChargePortDoorOpen{},
		},
	}))
	dump("charge_port_close", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_ChargePortDoorClose{
			ChargePortDoorClose: &carserver.ChargePortDoorClose{},
		},
	}))
	dump("schedule_charging", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_ScheduledChargingAction{
			ScheduledChargingAction: &carserver.ScheduledChargingAction{Enabled: true, ChargingTime: 120},
		},
	}))
	dump("schedule_departure", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_ScheduledDepartureAction{
			ScheduledDepartureAction: &carserver.ScheduledDepartureAction{
				Enabled:             true,
				DepartureTime:       480,
				OffPeakHoursEndTime: 360,
				PreconditioningTimes: &carserver.PreconditioningTimes{
					Times: &carserver.PreconditioningTimes_AllWeek{AllWeek: &carserver.Void{}},
				},
				OffPeakChargingTimes: &carserver.OffPeakChargingTimes{
					Times: &carserver.OffPeakChargingTimes_Weekdays{Weekdays: &carserver.Void{}},
				},
			},
		},
	}))
	dump("clear_departure", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_ScheduledDepartureAction{
			ScheduledDepartureAction: &carserver.ScheduledDepartureAction{Enabled: false},
		},
	}))
	dump("nearby", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_GetNearbyChargingSites{
			GetNearbyChargingSites: &carserver.GetNearbyChargingSites{
				IncludeMetaData: true,
				Radius:          200,
				Count:           10,
			},
		},
	}))
	dump("vent", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlWindowAction{
			VehicleControlWindowAction: &carserver.VehicleControlWindowAction{
				Action: &carserver.VehicleControlWindowAction_Vent{Vent: &carserver.Void{}},
			},
		},
	}))
	dump("get_charge_state", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_GetVehicleData{
			GetVehicleData: &carserver.GetVehicleData{GetChargeState: &carserver.GetChargeState{}},
		},
	}))
	dump("honk", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlHonkHornAction{
			VehicleControlHonkHornAction: &carserver.VehicleControlHonkHornAction{},
		},
	}))
	dump("flash", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlFlashLightsAction{
			VehicleControlFlashLightsAction: &carserver.VehicleControlFlashLightsAction{},
		},
	}))
	dump("close_windows", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlWindowAction{
			VehicleControlWindowAction: &carserver.VehicleControlWindowAction{
				Action: &carserver.VehicleControlWindowAction_Close{Close: &carserver.Void{}},
			},
		},
	}))
	dump("sunroof_80", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlSunroofOpenCloseAction{
			VehicleControlSunroofOpenCloseAction: &carserver.VehicleControlSunroofOpenCloseAction{
				SunroofLevel: &carserver.VehicleControlSunroofOpenCloseAction_AbsoluteLevel{AbsoluteLevel: 80},
			},
		},
	}))
	dump("sentry_on", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlSetSentryModeAction{
			VehicleControlSetSentryModeAction: &carserver.VehicleControlSetSentryModeAction{On: true},
		},
	}))
	dump("valet_1234", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlSetValetModeAction{
			VehicleControlSetValetModeAction: &carserver.VehicleControlSetValetModeAction{On: true, Password: "1234"},
		},
	}))
	dump("valet_off", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlSetValetModeAction{
			VehicleControlSetValetModeAction: &carserver.VehicleControlSetValetModeAction{On: false},
		},
	}))
	dump("guest_on", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_GuestModeAction{
			GuestModeAction: &carserver.VehicleState_GuestMode{GuestModeActive: true},
		},
	}))
	dump("ping", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_Ping{Ping: &carserver.Ping{PingId: 1}},
	}))
	dump("software_update_60", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlScheduleSoftwareUpdateAction{
			VehicleControlScheduleSoftwareUpdateAction: &carserver.VehicleControlScheduleSoftwareUpdateAction{
				OffsetSec: 60,
			},
		},
	}))
	dump("cancel_update", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlCancelSoftwareUpdateAction{
			VehicleControlCancelSoftwareUpdateAction: &carserver.VehicleControlCancelSoftwareUpdateAction{},
		},
	}))
	dump("homelink", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlTriggerHomelinkAction{
			VehicleControlTriggerHomelinkAction: &carserver.VehicleControlTriggerHomelinkAction{
				Location: &carserver.LatLong{Latitude: 37.4, Longitude: -122.1},
			},
		},
	}))
	dump("name_kyoto", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_SetVehicleNameAction{
			SetVehicleNameAction: &carserver.SetVehicleNameAction{VehicleName: "Kyoto"},
		},
	}))
	dump("media_prev", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_MediaPreviousTrack{
			MediaPreviousTrack: &carserver.MediaPreviousTrack{},
		},
	}))
	dump("volume_down", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_MediaUpdateVolume{
			MediaUpdateVolume: &carserver.MediaUpdateVolume{
				MediaVolume: &carserver.MediaUpdateVolume_VolumeDelta{VolumeDelta: -1},
			},
		},
	}))
	dump("parental_on", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_ParentalControlsAction{
			ParentalControlsAction: &carserver.ParentalControlsAction{Activate: true, Pin: "2468"},
		},
	}))
	dump("low_power", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_SetLowPowerModeAction{
			SetLowPowerModeAction: &carserver.SetLowPowerModeAction{LowPowerMode: true},
		},
	}))
	dump("accessory", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_SetKeepAccessoryPowerModeAction{
			SetKeepAccessoryPowerModeAction: &carserver.SetKeepAccessoryPowerModeAction{KeepAccessoryPowerMode: true},
		},
	}))
	dump("pin_admin", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlResetPinToDriveAdminAction{
			VehicleControlResetPinToDriveAdminAction: &carserver.VehicleControlResetPinToDriveAdminAction{},
		},
	}))
	dump("parental_speed", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_ParentalControlsSetSpeedLimitAction{
			ParentalControlsSetSpeedLimitAction: &carserver.ParentalControlsSetSpeedLimitAction{LimitMph: 65},
		},
	}))
	dump("add_charge_schedule", car(&carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_AddChargeScheduleAction{
			AddChargeScheduleAction: &carserver.ChargeSchedule{Id: 42, Name: "home", Enabled: true},
		},
	}))

	dump("lock", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_RKEAction{RKEAction: vcsec.RKEAction_E_RKE_ACTION_LOCK},
	})
	dump("unlock", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_RKEAction{RKEAction: vcsec.RKEAction_E_RKE_ACTION_UNLOCK},
	})
	dump("wake", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_RKEAction{RKEAction: vcsec.RKEAction_E_RKE_ACTION_WAKE_VEHICLE},
	})
	dump("auto_secure", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_RKEAction{RKEAction: vcsec.RKEAction_E_RKE_ACTION_AUTO_SECURE_VEHICLE},
	})
	dump("remote_drive", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_RKEAction{RKEAction: vcsec.RKEAction_E_RKE_ACTION_REMOTE_DRIVE},
	})
	dump("open_trunk", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_ClosureMoveRequest{
			ClosureMoveRequest: &vcsec.ClosureMoveRequest{RearTrunk: vcsec.ClosureMoveType_E_CLOSURE_MOVE_TYPE_MOVE},
		},
	})
	dump("close_trunk", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_ClosureMoveRequest{
			ClosureMoveRequest: &vcsec.ClosureMoveRequest{RearTrunk: vcsec.ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE},
		},
	})
	dump("open_frunk", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_ClosureMoveRequest{
			ClosureMoveRequest: &vcsec.ClosureMoveRequest{FrontTrunk: vcsec.ClosureMoveType_E_CLOSURE_MOVE_TYPE_MOVE},
		},
	})
	dump("open_tonneau", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_ClosureMoveRequest{
			ClosureMoveRequest: &vcsec.ClosureMoveRequest{Tonneau: vcsec.ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN},
		},
	})
	dump("close_tonneau", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_ClosureMoveRequest{
			ClosureMoveRequest: &vcsec.ClosureMoveRequest{Tonneau: vcsec.ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE},
		},
	})
	dump("stop_tonneau", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_ClosureMoveRequest{
			ClosureMoveRequest: &vcsec.ClosureMoveRequest{Tonneau: vcsec.ClosureMoveType_E_CLOSURE_MOVE_TYPE_STOP},
		},
	})
	dump("get_status", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_InformationRequest{
			InformationRequest: &vcsec.InformationRequest{
				InformationRequestType: vcsec.InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS,
			},
		},
	})
	dump("whitelist_info", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_InformationRequest{
			InformationRequest: &vcsec.InformationRequest{
				InformationRequestType: vcsec.InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO,
			},
		},
	})
	dump("whitelist_entry_3", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_InformationRequest{
			InformationRequest: &vcsec.InformationRequest{
				InformationRequestType: vcsec.InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_ENTRY_INFO,
				Key:                    &vcsec.InformationRequest_Slot{Slot: 3},
			},
		},
	})
	dump("remove_key", &vcsec.UnsignedMessage{
		SubMessage: &vcsec.UnsignedMessage_WhitelistOperation{
			WhitelistOperation: &vcsec.WhitelistOperation{
				SubMessage: &vcsec.WhitelistOperation_RemovePublicKeyFromWhitelist{
					RemovePublicKeyFromWhitelist: &vcsec.PublicKey{
						PublicKeyRaw: []byte{
							0x04, 0x2a, 0x01, 0xe3, 0x08, 0x84, 0x64, 0xb5, 0xe9, 0xf7, 0x2d, 0x68,
							0x79, 0x52, 0x27, 0xb2, 0xe9, 0x6b, 0xdc, 0x05, 0xb4, 0x79, 0x6d, 0xd5,
							0xa2, 0xcf, 0xc8, 0x6d, 0xa4, 0xde, 0x23, 0x37, 0xb8, 0xb2, 0xaf, 0x69,
							0x65, 0xea, 0xc9, 0x2e, 0x64, 0xc0, 0xfc, 0xdb, 0x8c, 0x5a, 0x07, 0xb7,
							0x64, 0xce, 0x6a, 0x01, 0xf4, 0x91, 0xef, 0xc5, 0x50, 0x88, 0xb5, 0xe1,
							0x98, 0x5f, 0x30, 0x4e, 0x63,
						},
					},
				},
			},
		},
	})
}
