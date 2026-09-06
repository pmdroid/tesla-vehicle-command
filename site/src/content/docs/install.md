---
title: Install
description: Add TeslaBLE to a host, ESP-IDF, or Arduino project
---

TeslaBLE is a static C++ library. It encodes Tesla vehicle-command messages and runs the BLE handshake. Plug in SimpleBLE, NimBLE, or the Arduino BLE stack for scan and GATT.

## Host (CMake)

Needs CMake 3.20+, a C++17 compiler, and network on first configure (FetchContent pulls nanopb 0.4.9.2, mbedtls 3.6.7, Catch2 for tests).

```bash
git clone https://github.com/pmdroid/tesla-vehicle-command.git
cd tesla-vehicle-command
cmake -B build -DTESLA_BLE_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Point another CMake project at this tree with `add_subdirectory` and link `TeslaBLE`. Tests are on when this repo is the top-level CMake project, or when you pass `-DTESLA_BLE_BUILD_TESTS=ON`.

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

`library.json` registers the library for PlatformIO on `espidf`. Add the GitHub URL as a lib dep, or copy `include/` and `src/` into the firmware tree. On ESP, mbedtls comes from ESP-IDF.

See `examples/esp32` (NimBLE, Seeed XIAO ESP32C3).

## Arduino

`examples/arduino` plus `arduino.sh` pack a zip the Arduino IDE can import. Arduino-esp32 uses mbedtls 2 through `MBEDTLS_VERSION_MAJOR`.
