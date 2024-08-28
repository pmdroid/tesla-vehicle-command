/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#include "metadata.h"

#ifdef ESP_PLATFORM
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif

#include <pb_decode.h>
#include <signatures.pb.h>
#include <universal_message.pb.h>

#include <shared.h>

namespace TeslaBLE {
    int MetaData::Start() {
        this->last_tag = 0;
        mbedtls_sha256_init(&this->sha256_context_);
        int return_code = mbedtls_sha256_starts(&this->sha256_context_, 0);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return ResultCode::SUCCESS;
    }

    int MetaData::BuildMetadata(UniversalMessage_Domain destination, Signatures_SignatureType method,
                                unsigned char *vin, uint32_t expiresAt, uint32_t counter, unsigned char *epoch) {
        unsigned char method_[1];
        memcpy(method_, &method, 1);
        int result_code = this->Add(Signatures_Tag_TAG_SIGNATURE_TYPE, method_, 1);
        if (result_code != ResultCode::SUCCESS) {
            return result_code;
        }

        unsigned char domain[1];
        memcpy(domain, &destination, 1);
        result_code = this->Add(Signatures_Tag_TAG_DOMAIN, domain, 1);
        if (result_code != ResultCode::SUCCESS) {
            return result_code;
        }

        result_code = this->Add(Signatures_Tag_TAG_PERSONALIZATION, vin, 17);
        if (result_code != ResultCode::SUCCESS) {
            return result_code;
        }

        result_code = this->Add(Signatures_Tag_TAG_EPOCH, epoch, 16);
        if (result_code != ResultCode::SUCCESS) {
            return result_code;
        }

        result_code = this->AddUint32(Signatures_Tag_TAG_EXPIRES_AT, expiresAt);
        if (result_code != ResultCode::SUCCESS) {
            return result_code;
        }

        return this->AddUint32(Signatures_Tag_TAG_COUNTER, counter);
    }

    int MetaData::Add(uint8_t signatures_tag, unsigned char *value, unsigned char value_size) {
        if (this->last_tag > signatures_tag) {
            return ResultCode::TAG_OUT_OF_ORDER;
        }

        if (value_size > 255) {
            return ResultCode::TAG_VALUE_TOO_LONG;
        }

        if (value_size == 0) {
            return ResultCode::TAG_VALUE_EMPTY;
        }

        this->last_tag = signatures_tag;

        int return_code = mbedtls_sha256_update(&this->sha256_context_, &signatures_tag, 1);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return_code = mbedtls_sha256_update(&this->sha256_context_, &value_size, 1);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return_code = mbedtls_sha256_update(&this->sha256_context_, value, value_size);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return ResultCode::SUCCESS;
    }

    int MetaData::AddUint32(const unsigned char signatures_tag, const uint32_t value) {
        unsigned char buffer[4];
        // Convert uint32_t to big-endian byte array
        buffer[0] = (value >> 24) & 0xFF;
        buffer[1] = (value >> 16) & 0xFF;
        buffer[2] = (value >> 8) & 0xFF;
        buffer[3] = value & 0xFF;

        return this->Add(signatures_tag, buffer, 4);
    }

    void MetaData::Checksum(unsigned char *output, const unsigned char end_tag) {
        int return_code = mbedtls_sha256_update(&this->sha256_context_, &end_tag, 1);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
        }

        return_code = mbedtls_sha256_finish(&this->sha256_context_, output);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
        }

        mbedtls_sha256_free(&this->sha256_context_);
    }
}
