/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#ifndef TESLA_BLE_SESSION_H
#define TESLA_BLE_SESSION_H

#include <car_server.pb.h>
#include <universal_message.pb.h>

#include <authenticator.h>
#include <metadata.h>

namespace TeslaBLE {
    class Session {
        std::map<UniversalMessage_Domain, uint32_t> time_zeros_;
        std::map<UniversalMessage_Domain, uint32_t> counters_;
        std::map<UniversalMessage_Domain, unsigned char[16]> epochs_;
        std::map<UniversalMessage_Domain, uint32_t> clock_times_;
        std::map<UniversalMessage_Domain, unsigned char[65]> car_keys;
        std::map<UniversalMessage_Domain, size_t> car_key_sizes;

        unsigned char vin_[17]{};
        unsigned char routing_address_[16]{};
        bool has_valid_session_info = false;

        MetaData meta_data_ = MetaData{};
        Authenticator *authenticator_ = nullptr;

    public:
        void LoadAuthenticator(Authenticator *authenticator);

        int LoadPrivateKey(unsigned char *private_key, size_t private_key_size);

        void LoadPrivateKeyContext(mbedtls_pk_context *shared_private_key_context_);

        void GenerateRoutingAddress();

        void SetRoutingAddress(unsigned char *routing_address);

        int UpdateSessionInfo(UniversalMessage_Domain domain, unsigned char *session_info_message,
                              size_t session_info_length);

        int BuildRoutableMessage(UniversalMessage_Domain domain, unsigned char *action_message_buffer,
                                 size_t action_message_buffer_size, unsigned char *output_buffer,
                                 size_t *output_buffer_size);

        int BuildActionMessage(UniversalMessage_Domain domain, const CarServer_VehicleAction *vehicle_action,
                               unsigned char *buffer, size_t *buffer_size);

        int BuildRequestSessionInfoMessage(UniversalMessage_Domain domain,
                                           unsigned char *output_buffer, size_t *output_length);

        uint32_t ExpiresAt(UniversalMessage_Domain domain, uint8_t expiresInSeconds);

        uint32_t Counter(UniversalMessage_Domain domain);

        void Epoch(UniversalMessage_Domain domain, unsigned char *output_buffer);

        void SetVIN(unsigned char *vin);

        int ExportSessionInfo(UniversalMessage_Domain domain, unsigned char *output_buffer, size_t *output_size);
    };
} // TeslaBLE


#endif //TESLA_BLE_SESSION_H
