## TeslaBLE::Shared Header File

### Overview
The `shared.h` header file provides common definitions, enums, and utility functions used across the TeslaBLE library. It serves as a central repository for shared data types and helper functions.

### Detailed Breakdown

#### Includes
* Includes necessary header files for standard data types (`cstdint`, `cstddef`), protocol buffer definitions (`universal_message.pb.h`, `vcsec.pb.h`), and possibly other shared definitions (`shared.h`).

#### ResultCode Enum
* Defines a set of error codes used throughout the library for indicating success or failure of various operations.
    * `SUCCESS`: Operation successful.
    * `ERROR`: Generic error.
    * `TAG_OUT_OF_ORDER`: Tag used in metadata is out of order.
    * `TAG_VALUE_EMPTY`: Tag value is empty.
    * `TAG_VALUE_TOO_LONG`: Tag value exceeds maximum length.
    * `MBEDTLS_ERROR`: Error occurred in MbedTLS library.
    * `NANOPB_ENCODE_ERROR`: Error occurred during NanoPB encoding.
    * `NANOPB_DECODE_ERROR`: Error occurred during NanoPB decoding.
    * `PRIVATE_KEY_NOT_LOADED`: Private key is not loaded.
    * `SESSION_INFO_NOT_LOADED`: Session information is not loaded.
    * `SESSION_INFO_KEY_NOT_WHITELISTED`: Session info key is not whitelisted.

#### Common Class
* Provides static utility functions for various operations.
    * `HexStrToUint8`: Converts a hexadecimal string to a byte array.
    * `DumpHexBuffer`: Prints a hexadecimal representation of a byte buffer to the console for debugging purposes.
    * `PrependLength`: Prepends the length of an input buffer to an output buffer.
    * `calculateIdentifier`: Calculates an identifier based on a VIN.
    * `ExtractLength`: Extracts the length from an input buffer.
    * `GenerateUUID`: Generates a UUID.
    * `DecodeRoutableMessage`: Decodes a routable message from a byte buffer using NanoPB.
    * `DecodeFromVCSECMessage`: Decodes a VCSEC message from a byte buffer using NanoPB.
    * `EncodeRoutableMessage`: Encodes a routable message to a byte buffer using NanoPB.
    * `ResultCodeToMessage`: Converts a result code to a human-readable message.
    * `ErrorCodeToMessage`: Converts a message fault enum to a human-readable message.
    * `OperationStatusToMessage`: Converts an operation status enum to a human-readable message.
    * `PrintErrorFromMbedTlsErrorCode`: Prints an error message based on an MbedTLS error code.
