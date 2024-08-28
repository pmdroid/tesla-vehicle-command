/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#ifndef TESLA_BLE_METADATA_H
#define TESLA_BLE_METADATA_H

#ifdef ESP_PLATFORM
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif

#include <mbedtls/sha256.h>

#include <universal_message.pb.h>
#include <signatures.pb.h>

namespace TeslaBLE {
    class MetaData {
        mbedtls_sha256_context sha256_context_{};
        uint8_t last_tag = 0;

        int Add(unsigned char signatures_tag, unsigned char *value, unsigned char value_length);

        int AddUint32(unsigned char signatures_tag, uint32_t value);

    public:
        int Start();

        int BuildMetadata(UniversalMessage_Domain destination, Signatures_SignatureType method,
                          unsigned char *vin,
                          uint32_t expiresAt, uint32_t counter, unsigned char *epoch);

        void Checksum(unsigned char *output, unsigned char end_tag);
    };
} // TeslaBLE

#endif //TESLA_BLE_METADATA_H
