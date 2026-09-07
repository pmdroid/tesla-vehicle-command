---
title: Send commands
description: CarServer and Security helpers, wrap, decode
---

Helpers encode Tesla protobufs. You write the wrapped buffer over GATT.

1. Call `CarServer::*` or `Security::*` into a buffer.
2. Wrap with `Session::BuildRoutableMessage` on the matching domain.
3. Write the result. Reassemble the reply with `BleFrame`, then decode.

```cpp
unsigned char action[256];
size_t action_size = 0;
TeslaBLE::CarServer::TurnOnClimate(action, &action_size);

unsigned char out[UniversalMessage_RoutableMessage_size];
size_t out_size = 0;
session.BuildRoutableMessage(
    UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
    action,
    action_size,
    out,
    &out_size);
```

Lock, unlock, wake, trunks, and GetStatus use `DOMAIN_VEHICLE_SECURITY` and `Security::*`. Climate, charge, media, and GetVehicleData use `DOMAIN_INFOTAINMENT` and `CarServer::*`.

## Security (VCSEC)

`Lock`, `Unlock`, `Wake`, `AutoSecure`, `RemoteDrive`, `OpenTrunk`, `CloseTrunk`, `OpenFrunk`, `OpenTonneau`, `CloseTonneau`, `StopTonneau`, `GetStatus`, `GetWhitelistInfo`, `GetWhitelistEntryInfo`, `RemoveKey`.

Decode replies with `Common::DecodeFromVCSECMessage`.

## CarServer (Infotainment)

Climate on/off, driver/passenger °C, seats, COP, bioweapon, climate keeper, charge start/stop/limit/amps/max/standard, charge port, schedules, nearby sites, honk, flash, windows, sunroof, sentry, valet, guest, ping, software update, homelink, vehicle name, media, volume, parental controls, PIN admin reset, low-power, accessory power.

`GetVehicleData` takes one `VehicleDataCategory` per request (BLE MTU). Categories: charge, climate, drive, location, closures, charge schedule, preconditioning schedule, tire pressure, media, media detail, software update, parental controls.

Decode with `Common::DecodeCarServerResponse`.
