---
title: BLE framing
description: Advertisement name, GATT UUIDs, length prefix, ATT reassembly
---

This library does not scan or connect. Use SimpleBLE, NimBLE, or the Arduino BLE stack. Feed bytes in and out.

## Find the car

`Common::calculateIdentifier` turns the 17-byte VIN into the BLE advertisement name (Tesla `protocol.md` S1…C form). Scan until a peripheral matches that name.

## GATT

| Role | UUID |
| --- | --- |
| Service | `00000211-b2d1-43f0-9b88-960cebf8b91e` |
| Write | `00000212-b2d1-43f0-9b88-960cebf8b91e` |
| Indicate | `00000213-b2d1-43f0-9b88-960cebf8b91e` |

## Length prefix

Every Tesla BLE payload starts with a 2-byte big-endian length, then that many protobuf bytes. `BuildRoutableMessage` already prepends it. `Common::ExtractLength` / `PrependLength` exist if you need them by hand.

## ATT fragments

Indications can split a message across packets. Push each chunk into `BleFrame::Add`. `COMPLETE` means `Payload()` / `PayloadSize()` is the full RoutableMessage (length prefix included). `ERROR` means reset. `NEED_MORE` means wait.

```cpp
TeslaBLE::BleFrame frame;
auto status = frame.Add(chunk, chunk_size);
if (status == TeslaBLE::BleFrame::COMPLETE) {
    UniversalMessage_RoutableMessage msg = UniversalMessage_RoutableMessage_init_zero;
    TeslaBLE::Common::DecodeRoutableMessage(
        const_cast<unsigned char *>(frame.Payload()),
        frame.PayloadSize(),
        &msg);
    frame.Reset();
}
```

See `examples/simple` and `examples/esp32` for a full scan-connect-indicate loop.
