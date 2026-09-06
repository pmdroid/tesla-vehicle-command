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
        static constexpr unsigned kDomainSlots = 4;
        uint32_t time_zeros_[kDomainSlots]{};
        uint32_t counters_[kDomainSlots]{};
        unsigned char epochs_[kDomainSlots][16]{};
        uint32_t clock_times_[kDomainSlots]{};
        unsigned char car_keys[kDomainSlots][65]{};
        size_t car_key_sizes[kDomainSlots]{};
        bool has_valid_session_info_[kDomainSlots]{};
        unsigned char request_uuids_[kDomainSlots][16]{};
        size_t request_uuid_sizes_[kDomainSlots]{};

        unsigned char vin_[17]{};
        unsigned char routing_address_[16]{};

        MetaData meta_data_ = MetaData{};
        Authenticator *authenticator_ = nullptr;

    public:
        void LoadAuthenticator(Authenticator *authenticator);

        int GenerateRoutingAddress();

        void SetRoutingAddress(unsigned char *routing_address);

        void SetRequestUuid(UniversalMessage_Domain domain, unsigned char *uuid, size_t uuid_size);

        int UpdateSessionInfo(UniversalMessage_Domain domain, unsigned char *session_info_message,
                              size_t session_info_length, unsigned char *tag, size_t tag_length);

        int BuildRoutableMessage(UniversalMessage_Domain domain, unsigned char *action_message_buffer,
                                 size_t action_message_buffer_size, unsigned char *output_buffer,
                                 size_t *output_buffer_size);

        int BuildRequestSessionInfoMessage(UniversalMessage_Domain domain,
                                           unsigned char *output_buffer, size_t *output_length);

        uint32_t ExpiresAt(UniversalMessage_Domain domain, uint8_t expiresInSeconds);

        uint32_t Counter(UniversalMessage_Domain domain);

        void Epoch(UniversalMessage_Domain domain, unsigned char *output_buffer);

        void SetVIN(unsigned char *vin);

        int ExportSessionInfo(UniversalMessage_Domain domain, unsigned char *output_buffer, size_t *output_size);

        int ImportSessionInfo(UniversalMessage_Domain domain, unsigned char *input_buffer, size_t input_size);
    };
} // TeslaBLE


#endif //TESLA_BLE_SESSION_H
