## TeslaBLE::Security Class

### Overview
The `TeslaBLE::Security` class encapsulates security-related operations within the TeslaBLE library. Based on the provided header, it appears to handle message encryption and decryption processes, likely using the `VCSEC_UnsignedMessage` structure defined in the `vcsec.pb.h` file.

### Public Methods

#### `static int Unlock(unsigned char *buffer, size_t *buffer_size)`
* **Purpose:** Decrypts the provided buffer.
* **Parameters:**
    * `buffer`: The encrypted data buffer.
    * `buffer_size`: The size of the input buffer and output buffer.
* **Returns:** An integer indicating success or failure.

#### `static int Lock(unsigned char *buffer, size_t *buffer_size)`
* **Purpose:** Encrypts the provided buffer.
* **Parameters:**
    * `buffer`: The plaintext data buffer.
    * `buffer_size`: The size of the input buffer and output buffer.
* **Returns:** An integer indicating success or failure.

### Private Methods
#### `static int BuildUnsignedMessage(const VCSEC_UnsignedMessage *unsigned_message, unsigned char *buffer, size_t *buffer_size)`
* **Purpose:** Builds an unsigned message based on the provided `VCSEC_UnsignedMessage` structure.
* **Parameters:**
    * `unsigned_message`: The unsigned message structure.
    * `buffer`: The output buffer to hold the encoded message.
    * `buffer_size`: The size of the output buffer.
* **Returns:** An integer indicating success or failure.
