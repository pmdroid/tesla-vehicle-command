---
title: Install
description: Add TeslaBLE to a host, ESP-IDF, or Arduino project
---

TeslaBLE is a static C++ library. It encodes Tesla vehicle-command messages and runs the BLE handshake. It does not open a BLE stack for you.

## Host (CMake)

Needs CMake 3.20+, a C++17 compiler, and network on first configure (FetchContent pulls nanopb 0.4.9.2, mbedtls 3.6.7, Catch2 for tests).

```bash
git clone https://github.com/pmdroid/tesla-vehicle-command.git
cd tesla-vehicle-command
cmake -B build -DTESLA_BLE_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Point another CMake project at this tree with `add_subdirectory` and link `TeslaBLE`. When this repo is not the top-level project, tests stay off unless you pass `-DTESLA_BLE_BUILD_TESTS=ON`.

Headers live in `include/`. Call them as:

```cpp
#include <authenticator.h>
#include <session.h>
#include <carserver.h>
#include <security.h>
#include <shared.h>
#include <ble_frame.h>
```

## ESP-IDF / PlatformIO

`library.json` registers the library for PlatformIO on `espidf`. Add the GitHub URL as a lib dep, or copy `include/` and `src/` into the firmware tree. On ESP, mbedtls comes from ESP-IDF. Do not link the host FetchContent mbedtls.

See `examples/esp32` (NimBLE, Seeed XIAO ESP32C3).

## Arduino

`examples/arduino` plus `arduino.sh` pack a zip the Arduino IDE can import. Arduino-esp32 still uses mbedtls 2. The library keeps mbedtls 2 paths behind `MBEDTLS_VERSION_MAJOR`.

## What this library is not

Tesla Fleet HTTPS, `SetPINToDrive`, HMAC-personalized command MACs, and tesla-http-proxy are out of scope. Those live in teslamotors/vehicle-command (Go) on TLS, not BLE.
