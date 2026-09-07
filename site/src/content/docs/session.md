---
title: Open a session
description: VIN, routing address, session-info HMAC, encrypt-response
---

A session is per domain. VCSEC (`DOMAIN_VEHICLE_SECURITY`) and Infotainment (`DOMAIN_INFOTAINMENT`) each have their own epoch, counter, clock, and 16-byte shared secret.

## Bind VIN and authenticator

VIN is 17 bytes. `SetVIN` copies those 17 bytes.

```cpp
TeslaBLE::Session session;
unsigned char vin[17];
memcpy(vin, "XP7YGCEL9NB000000", 17);

session.SetVIN(vin);
session.GenerateRoutingAddress();
session.LoadAuthenticator(&authenticator);
```

One `Authenticator` is shared. Shared secrets sit in per-domain slots on that authenticator.

## Request session info

Do this before any encrypted command, and again after a car software update.

```cpp
unsigned char req[200];
size_t req_size = 0;
session.BuildRequestSessionInfoMessage(
    UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
    req,
    &req_size);
```

Send `req`. Repeat for `DOMAIN_INFOTAINMENT`.

## Apply the reply

The RoutableMessage payload is the session-info protobuf. The HMAC tag is in `signature_data.session_info_tag`. Both are required:

```cpp
session.UpdateSessionInfo(
    domain,
    session_info_bytes,
    session_info_size,
    tag,
    tag_size);
```

`UpdateSessionInfo` verifies the HMAC, then stores epoch, counter, and clock.

## Persist across reboot

```cpp
unsigned char blob[128];
size_t blob_size = 0;
session.ExportSessionInfo(domain, blob, &blob_size);
session.ImportSessionInfo(domain, blob, blob_size);
```

## Encrypted commands

`BuildRoutableMessage` AES-GCM encrypts the helper payload, binds metadata (VIN, domain, counter, epoch, `FLAG_ENCRYPT_RESPONSE`), and prepends the 2-byte BLE length. You write that buffer to the car.
