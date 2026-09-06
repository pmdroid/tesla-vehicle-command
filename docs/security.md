# TeslaBLE::Security

Builds VCSEC unsigned RKE payloads. These are not encrypt/decrypt helpers.

- `Unlock` encodes `RKE_ACTION_UNLOCK`
- `Lock` encodes `RKE_ACTION_LOCK`
- `Wake` encodes `RKE_ACTION_WAKE_VEHICLE`

Wrap the bytes with `Session::BuildRoutableMessage` for `DOMAIN_VEHICLE_SECURITY` before sending.
