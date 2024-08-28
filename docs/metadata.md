## TeslaBLE::MetaData Class Documentation

### Overview
The `TeslaBLE::MetaData` class is responsible for generating metadata for Tesla BLE communication. It utilizes the `mbedtls` library for SHA256 hashing and the `universal_message.pb.h` and `signatures.pb.h` protocol buffers for message structuring.

### Public Methods

#### `int Start()`
* **Purpose:** Initializes the metadata generation process.
* **Returns:** An integer indicating success or failure.

#### `int BuildMetadata(UniversalMessage_Domain destination, Signatures_SignatureType method, unsigned char *vin, uint32_t expiresAt, uint32_t counter, unsigned char *epoch)`
* **Purpose:** Constructs metadata for a specific message.
* **Parameters:**
    * `destination`: The destination domain of the message.
    * `method`: The signature method used for the message.
    * `vin`: The vehicle identification number (VIN).
    * `expiresAt`: The expiration timestamp of the metadata.
    * `counter`: A message counter.
    * `epoch`: An epoch value.
* **Returns:** An integer indicating success or failure.

#### `void Checksum(unsigned char *output, unsigned char end_tag)`
* **Purpose:** Calculates the checksum of the generated metadata.
* **Parameters:**
    * `output`: A buffer to store the calculated checksum.
    * `end_tag`: The ending tag for the checksum calculation.

### Private Members

#### `mbedtls_sha256_context sha256_context_`
* **Purpose:** Stores the SHA256 context for checksum calculation.

#### `uint8_t last_tag`
* **Purpose:** Tracks the last used tag for metadata construction.

#### `int Add(unsigned char signatures_tag, unsigned char *value, unsigned char value_length)`
* **Purpose:** Adds data to the metadata with a specific tag.
* **Parameters:**
    * `signatures_tag`: The tag identifying the data.
    * `value`: The data to be added.
    * `value_length`: The length of the data.
* **Returns:** An integer indicating success or failure.

#### `int AddUint32(unsigned char signatures_tag, uint32_t value)`
* **Purpose:** Adds a 32-bit unsigned integer to the metadata with a specific tag.
* **Parameters:**
    * `signatures_tag`: The tag identifying the data.
    * `value`: The 32-bit unsigned integer value.
* **Returns:** An integer indicating success or failure.