---
title: Pair a key
description: Create or load a P-256 key and whitelist it with the vehicle
---

Every command is signed with a key the car already trusts. Pairing is a one-time whitelist on VCSEC.

## Create or load the key

```cpp
TeslaBLE::Authenticator authenticator;

authenticator.CreatePrivateKey();
```

Or load a PEM you already stored:

```cpp
const unsigned char pem[] = "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----";
authenticator.LoadPrivateKey(pem, sizeof pem);
```

Export the PEM and load it on the next boot:

```cpp
unsigned char pem_out[256];
size_t pem_size = 0;
authenticator.GetPrivateKey(pem_out, sizeof pem_out, &pem_size);
```

`Authenticator::LoadPrivateKey` takes the PEM bytes and size.

## Whitelist

```cpp
unsigned char buffer[256];
size_t size = 0;
authenticator.BuildKeyWhitelistMessage(
    Keys_Role_ROLE_OWNER,
    VCSEC_KeyFormFactor_KEY_FORM_FACTOR_ANDROID_DEVICE,
    buffer,
    &size);
```

`ROLE_GUEST` is valid. Form factor is an argument. Send `buffer` over the VCSEC BLE characteristic (see [BLE framing](../ble/)).

The car replies with an operation status:

| Status | Meaning |
| --- | --- |
| `OPERATIONSTATUS_OK` | Key is on the whitelist |
| `OPERATIONSTATUS_WAIT` | Present the NFC card, then retry |
| `OPERATIONSTATUS_ERROR` | Rejected |

After `OPERATIONSTATUS_OK`, request session info. `UpdateSessionInfo` decodes the VCSEC status before it stores epoch and counter.
