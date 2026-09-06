/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#ifndef TESLA_BLE_AUTHENTICATOR_H_INCLUDED
#define TESLA_BLE_AUTHENTICATOR_H_INCLUDED

#ifdef ESP_PLATFORM
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif

#include <shared.h>
#include <keys.pb.h>
#include <map>

#include "pb.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha1.h"

namespace TeslaBLE {
  class Authenticator {
    mbedtls_pk_context private_key_context_{};
    mbedtls_ecdh_context ecdh_context_{};
    mbedtls_ctr_drbg_context drbg_context_{};

    size_t public_key_size_ = 0;
    unsigned char public_key_[65]{};
    unsigned char nonce_[12] = {};
    bool private_key_loaded_ = false;
    std::map<UniversalMessage_Domain, unsigned char[16]> shared_secrets_;

    int GeneratePublicKey();

    int UpdateNonce();

  public:
    Authenticator() = default;
    ~Authenticator() { Cleanup(); }
    Authenticator(const Authenticator &) = delete;
    Authenticator &operator=(const Authenticator &) = delete;

    int BuildKeyWhitelistMessage(Keys_Role role, unsigned char *output_buffer, size_t *output_size);

    int CreatePrivateKey();

    int Encrypt(UniversalMessage_Domain domain, unsigned char *input_buffer,
                size_t input_buffer_size,
                unsigned char *checksum, unsigned char *output_buffer, size_t output_buffer_size,
                size_t *output_size, unsigned char *tag_buffer);

    int EncryptWithNonce(UniversalMessage_Domain domain, unsigned char *input_buffer,
                         size_t input_buffer_size, unsigned char *checksum,
                         unsigned char *nonce, size_t nonce_size,
                         unsigned char *output_buffer, size_t output_buffer_size,
                         size_t *output_size, unsigned char *tag_buffer);

    int Decrypt(UniversalMessage_Domain domain, unsigned char *nonce, size_t nonce_size,
                unsigned char *input_buffer, size_t input_buffer_size,
                unsigned char *checksum, unsigned char *tag, size_t tag_size,
                unsigned char *output_buffer, size_t output_buffer_size,
                size_t *output_size);

    int LoadPrivateKey(const uint8_t *private_key_buffer, size_t key_size);

    int GetPrivateKey(unsigned char *output_buffer, size_t buffer_size, size_t *output_size);

    int LoadTeslaPublicKey(UniversalMessage_Domain domain, const uint8_t *public_key_buffer,
                           size_t public_key_size);

    void GetNonce(unsigned char *nonce);

    int GetSharedSecret(UniversalMessage_Domain domain, unsigned char *output_buffer, size_t output_size);

    void ClearSharedSecret(UniversalMessage_Domain domain);

    int VerifySessionInfoTag(UniversalMessage_Domain domain, unsigned char *vin,
                             unsigned char *challenge, size_t challenge_size,
                             unsigned char *session_info, size_t session_info_size,
                             unsigned char *tag, size_t tag_size);

    void GetPublicKey(unsigned char *output_buffer, pb_size_t *output_size);

    void Cleanup();
  };
} // namespace TeslaBLE
#endif  // TESLA_BLE_AUTHENTICATOR_H_INCLUDED
