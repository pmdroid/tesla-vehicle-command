---
title: Host, ESP-IDF, Arduino
description: Which example to copy for each platform
---

## Host

`examples/simple` uses SimpleBLE. It scans for the VIN advertisement, subscribes to indications, and reassembles with `BleFrame`. Good for a laptop sitting next to the car.

Host crypto is mbedtls 3.6.7 via CMake FetchContent.

## ESP-IDF

`examples/esp32` uses NimBLE. Serial keys 1-5 send climate on/off, next track, lock, unlock. Same whitelist and session-info flow as host.

ESP-IDF supplies mbedtls. Keep `ESP_PLATFORM` so headers pick `mbedtls/esp_config.h`.

## Arduino

`examples/arduino` plus `arduino.sh`. Arduino-esp32 is mbedtls 2. Encrypt, decrypt, and key parse go through `MBEDTLS_VERSION_MAJOR`.

## Tests

Host Catch2 lives in `tests/`. Tesla `protocol.md` vectors cover metadata SHA-256, ECDH, AES-GCM with `FLAG_ENCRYPT_RESPONSE`, and session-info HMAC. `tests/goldens` compares C++ helper bytes to Tesla Go `proto.Marshal` at `f97fa1e`.
