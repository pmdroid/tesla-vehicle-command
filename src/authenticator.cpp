/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#include <authenticator.h>

#ifdef ESP_PLATFORM
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif

#include <cstdlib>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha1.h>

#include <pb.h>
#include <pb_encode.h>

#include <shared.h>
#include <keys.pb.h>
#include <vcsec.pb.h>

namespace TeslaBLE {
    void Authenticator::UpdateNonce() {
        for (unsigned char &i: this->nonce_) {
            i = rand() % 256;
        }
    }

    void Authenticator::GetNonce(unsigned char *nonce) {
        memcpy(nonce, this->nonce_, 12);
    }

    int Authenticator::BuildKeyWhitelistMessage(Keys_Role role, unsigned char *output_buffer,
                                                size_t *output_size) {
        if (!this->private_key_loaded_) {
            return ResultCode::PRIVATE_KEY_NOT_LOADED;
        }

        VCSEC_PermissionChange permission_change = VCSEC_PermissionChange_init_default;
        memcpy(permission_change.key.PublicKeyRaw.bytes, this->public_key_, this->public_key_size_);
        permission_change.key.PublicKeyRaw.size = this->public_key_size_;
        permission_change.keyRole = role;
        permission_change.has_key = true;

        VCSEC_WhitelistOperation whitelist_operation = VCSEC_WhitelistOperation_init_default;
        whitelist_operation.metadataForKey.keyFormFactor = VCSEC_KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY;
        whitelist_operation.has_metadataForKey = true;

        whitelist_operation.which_sub_message = VCSEC_WhitelistOperation_addKeyToWhitelistAndAddPermissions_tag;
        whitelist_operation.sub_message.addKeyToWhitelistAndAddPermissions = permission_change;

        VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_default;
        unsigned_message.which_sub_message = VCSEC_UnsignedMessage_WhitelistOperation_tag;
        unsigned_message.sub_message.WhitelistOperation = whitelist_operation;

        pb_ostream_t unsigned_message_size_stream = {nullptr};
        if (!pb_encode(&unsigned_message_size_stream, VCSEC_UnsignedMessage_fields, &unsigned_message)) {
            printf("Failed to encode message: %s", PB_GET_ERROR(&unsigned_message_size_stream));
            return ResultCode::MBEDTLS_ERROR;
        }

        uint8_t unsigned_message_buffer[unsigned_message_size_stream.bytes_written];
        pb_ostream_t unsigned_message_stream = pb_ostream_from_buffer(unsigned_message_buffer,
                                                                      unsigned_message_size_stream.bytes_written);
        if (!pb_encode(&unsigned_message_stream, VCSEC_UnsignedMessage_fields, &unsigned_message)) {
            printf("Failed to encode message: %s", PB_GET_ERROR(&unsigned_message_stream));
            return ResultCode::MBEDTLS_ERROR;
        }

        VCSEC_SignedMessage signed_message = VCSEC_SignedMessage_init_default;
        signed_message.signatureType = VCSEC_SignatureType_SIGNATURE_TYPE_PRESENT_KEY;
        memcpy(signed_message.protobufMessageAsBytes.bytes, &unsigned_message_buffer,
               unsigned_message_size_stream.bytes_written);
        signed_message.protobufMessageAsBytes.size = unsigned_message_size_stream.bytes_written;

        VCSEC_ToVCSECMessage vcsec_message = VCSEC_ToVCSECMessage_init_default;
        vcsec_message.signedMessage = signed_message;
        vcsec_message.has_signedMessage = true;

        pb_ostream_t signed_message_size_stream = {nullptr};
        if (!pb_encode(&signed_message_size_stream, VCSEC_ToVCSECMessage_fields, &vcsec_message)) {
            printf("Failed to encode message: %s", PB_GET_ERROR(&signed_message_size_stream));
            return ResultCode::MBEDTLS_ERROR;
        }

        uint8_t signed_message_buffer[signed_message_size_stream.bytes_written];
        pb_ostream_t signed_message_stream = pb_ostream_from_buffer(signed_message_buffer,
                                                                    signed_message_size_stream.bytes_written);
        if (!pb_encode(&signed_message_stream, VCSEC_ToVCSECMessage_fields, &vcsec_message)) {
            printf("Failed to encode message: %s", PB_GET_ERROR(&signed_message_stream));
            return ResultCode::MBEDTLS_ERROR;
        }

        Common::PrependLength(signed_message_buffer, signed_message_stream.bytes_written, output_buffer, output_size);
        return ResultCode::SUCCESS;
    }

    int Authenticator::CreatePrivateKey() {
        mbedtls_entropy_context entropy_context;
        mbedtls_entropy_init(&entropy_context);
        mbedtls_pk_init(&this->private_key_context_);
        mbedtls_ctr_drbg_init(&this->drbg_context_);

        int return_code = mbedtls_ctr_drbg_seed(&drbg_context_, mbedtls_entropy_func,
                                                &entropy_context, nullptr, 0);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return_code = mbedtls_pk_setup(
            &this->private_key_context_,
            mbedtls_pk_info_from_type((mbedtls_pk_type_t) MBEDTLS_PK_ECKEY));

        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return_code = mbedtls_ecp_gen_key(
            MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(this->private_key_context_),
            mbedtls_ctr_drbg_random, &this->drbg_context_);

        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        this->private_key_loaded_ = true;
        return this->GeneratePublicKey();
    }

    int Authenticator::LoadPrivateKey(const uint8_t *private_key_buffer,
                                      size_t private_key_size) {
        mbedtls_entropy_context entropy_context;
        mbedtls_entropy_init(&entropy_context);

        mbedtls_pk_init(&this->private_key_context_);
        mbedtls_ctr_drbg_init(&this->drbg_context_);

        int return_code = mbedtls_ctr_drbg_seed(&drbg_context_, mbedtls_entropy_func,
                                                &entropy_context, nullptr, 0);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        unsigned char password[0];
        return_code = mbedtls_pk_parse_key(
            &this->private_key_context_, private_key_buffer, private_key_size,
            password, 0, mbedtls_ctr_drbg_random, &this->drbg_context_);

        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        this->private_key_loaded_ = true;
        return this->GeneratePublicKey();
    }

    int Authenticator::GetPrivateKey(unsigned char *output_buffer,
                                     size_t output_buffer_size, size_t *output_size) {
        int return_code = mbedtls_pk_write_key_pem(
            &this->private_key_context_, output_buffer, output_buffer_size);

        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        *output_size = strlen((char *) output_buffer) + 1;
        return ResultCode::SUCCESS;
    }

    void Authenticator::GetPublicKey(unsigned char *output_buffer, pb_size_t *output_size) {
        memcpy(output_buffer, this->public_key_, this->public_key_size_);
        *output_size = this->public_key_size_;
    }

    int Authenticator::GeneratePublicKey() {
        int return_code = mbedtls_ecp_point_write_binary(
            &mbedtls_pk_ec(this->private_key_context_)->private_grp,
            &mbedtls_pk_ec(this->private_key_context_)->private_Q,
            MBEDTLS_ECP_PF_UNCOMPRESSED, &this->public_key_size_, this->public_key_,
            sizeof(this->public_key_));

        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return ResultCode::SUCCESS;
    }

    int Authenticator::LoadTeslaPublicKey(UniversalMessage_Domain domain, const uint8_t *public_key_buffer,
                                          size_t public_key_size) {
        if (!this->private_key_loaded_) {
            return ResultCode::PRIVATE_KEY_NOT_LOADED;
        }

        mbedtls_ecp_keypair tesla_key;
        mbedtls_ecp_keypair_init(&tesla_key);

        unsigned char temp_shared_secret[32];
        size_t temp_shared_secret_length = 0;

        int return_code = mbedtls_ecp_group_load(&tesla_key.private_grp,
                                                 MBEDTLS_ECP_DP_SECP256R1);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return_code = mbedtls_ecp_point_read_binary(
            &tesla_key.private_grp, &tesla_key.private_Q,
            public_key_buffer, public_key_size);

        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        mbedtls_ecdh_init(&this->ecdh_context_);
        return_code = mbedtls_ecdh_get_params(
            &this->ecdh_context_, mbedtls_pk_ec(this->private_key_context_),
            MBEDTLS_ECDH_OURS);

        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return_code = mbedtls_ecdh_get_params(&this->ecdh_context_, &tesla_key,
                                              MBEDTLS_ECDH_THEIRS);

        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return_code =
                mbedtls_ecdh_calc_secret(&this->ecdh_context_, &temp_shared_secret_length,
                                         temp_shared_secret, sizeof(temp_shared_secret),
                                         mbedtls_ctr_drbg_random, &this->drbg_context_);

        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        mbedtls_sha1_context sha1_context;
        mbedtls_sha1_init(&sha1_context);

        return_code = mbedtls_sha1_starts(&sha1_context);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return_code = mbedtls_sha1_update(&sha1_context, temp_shared_secret,
                                          temp_shared_secret_length);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return_code = mbedtls_sha1_finish(&sha1_context, this->shared_secrets_[domain]);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        mbedtls_sha1_free(&sha1_context);
        mbedtls_ecp_keypair_free(&tesla_key);
        return ResultCode::SUCCESS;
    }

    int Authenticator::Encrypt(UniversalMessage_Domain domain, unsigned char *input_buffer,
                               size_t input_buffer_size, unsigned char *checksum,
                               unsigned char *output_buffer, size_t output_buffer_size,
                               size_t *output_size, unsigned char *tag_buffer) {
        mbedtls_gcm_context aes_context;
        mbedtls_gcm_init(&aes_context);

        this->UpdateNonce();
        int return_code = mbedtls_gcm_setkey(&aes_context, MBEDTLS_CIPHER_ID_AES,
                                             this->shared_secrets_[domain],
                                             128);

        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return_code = mbedtls_gcm_starts(&aes_context, MBEDTLS_GCM_ENCRYPT, this->nonce_,
                                         12);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return_code = mbedtls_gcm_update_ad(&aes_context, checksum, 32);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        return_code =
                mbedtls_gcm_update(&aes_context, input_buffer, input_buffer_size,
                                   output_buffer, output_buffer_size, output_size);

        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        size_t finish_buffer_length = 0;
        unsigned char finish_buffer[15];

        return_code =
                mbedtls_gcm_finish(&aes_context, finish_buffer, sizeof(finish_buffer),
                                   &finish_buffer_length, tag_buffer, 16);

        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return ResultCode::MBEDTLS_ERROR;
        }

        if (finish_buffer_length > 0) {
            memcpy(output_buffer + *output_size, finish_buffer, finish_buffer_length);
            *output_size = output_buffer_size + finish_buffer_length;
        }

        mbedtls_gcm_free(&aes_context);
        return ResultCode::SUCCESS;
    }

    void Authenticator::Cleanup() {
        mbedtls_pk_free(&this->private_key_context_);
        mbedtls_ecdh_free(&this->ecdh_context_);
        mbedtls_ctr_drbg_free(&this->drbg_context_);
    }
} // namespace TeslaBLE
