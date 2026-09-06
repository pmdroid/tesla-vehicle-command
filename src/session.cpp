/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#include "session.h"

#include <cstdio>
#include <chrono>
#include <cstdlib>

#include <ctime>

#include <car_server.pb.h>
#include <signatures.pb.h>
#include <universal_message.pb.h>

#include <pb.h>
#include <pb_decode.h>
#include <pb_encode.h>

#include <shared.h>

namespace TeslaBLE {
    void Session::LoadAuthenticator(Authenticator *authenticator) {
        this->authenticator_ = authenticator;
    }

    int Session::GenerateRoutingAddress() {
        return Common::RandomBytes(this->routing_address_, sizeof(this->routing_address_));
    }

    void Session::SetRoutingAddress(unsigned char *routing_address) {
        memcpy(this->routing_address_, routing_address, 16);
    }

    uint32_t Session::ExpiresAt(UniversalMessage_Domain domain, uint8_t expiresInSeconds) {
        return std::chrono::system_clock::to_time_t(
                   std::chrono::system_clock::now() + std::chrono::seconds(expiresInSeconds)) - this->
               time_zeros_[domain];
    }

    // always increases the counter
    uint32_t Session::Counter(UniversalMessage_Domain domain) {
        this->counters_[domain] = this->counters_[domain] + 1;
        return this->counters_[domain];
    }

    void Session::Epoch(UniversalMessage_Domain domain, unsigned char *output_buffer) {
        memcpy(output_buffer, this->epochs_[domain], 16);
    }

    void Session::SetVIN(unsigned char *vin) {
        memcpy(this->vin_, vin, 17);
    }

    int Session::ExportSessionInfo(UniversalMessage_Domain domain, unsigned char *output_buffer,
                                   size_t *output_size) {
        Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;

        session_info.clock_time = this->clock_times_[domain];
        session_info.counter = this->counters_[domain];
        session_info.status = Signatures_Session_Info_Status_SESSION_INFO_STATUS_OK;
        memcpy(session_info.epoch, this->epochs_[domain], 16);
        memcpy(session_info.publicKey.bytes, this->car_keys[domain], this->car_key_sizes[domain]);
        session_info.publicKey.size = this->car_key_sizes[domain];

        pb_ostream_t message_stream = pb_ostream_from_buffer(output_buffer, Signatures_SessionInfo_size);
        if (!pb_encode(&message_stream, Signatures_SessionInfo_fields, &session_info)) {
            printf("Failed to encode message: %s", PB_GET_ERROR(&message_stream));
            return ResultCode::NANOPB_ENCODE_ERROR;
        }

        *output_size = message_stream.bytes_written;
        return ResultCode::SUCCESS;
    }

    void Session::SetRequestUuid(UniversalMessage_Domain domain, unsigned char *uuid, size_t uuid_size) {
        size_t copy = uuid_size;
        if (copy > 16) {
            copy = 16;
        }
        memcpy(this->request_uuids_[domain], uuid, copy);
        this->request_uuid_sizes_[domain] = copy;
    }

    int Session::UpdateSessionInfo(UniversalMessage_Domain domain, unsigned char *session_info_message,
                                   size_t session_info_length, unsigned char *tag, size_t tag_length) {
        Signatures_SessionInfo session_info = Signatures_SessionInfo_init_zero;

        pb_istream_t stream = pb_istream_from_buffer(session_info_message, session_info_length);
        if (!pb_decode(&stream, Signatures_SessionInfo_fields, &session_info)) {
            printf("Failed to decode session info: %s\n", PB_GET_ERROR(&stream));
            return ResultCode::NANOPB_DECODE_ERROR;
        }

        if (session_info.status == Signatures_Session_Info_Status_SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST) {
            this->has_valid_session_info_[domain] = false;
            return ResultCode::SESSION_INFO_KEY_NOT_WHITELISTED;
        }

        if (this->authenticator_ == nullptr) {
            return ResultCode::PRIVATE_KEY_NOT_LOADED;
        }

        int result = this->authenticator_->LoadTeslaPublicKey(domain, session_info.publicKey.bytes,
                                                              session_info.publicKey.size);
        if (result != ResultCode::SUCCESS) {
            this->has_valid_session_info_[domain] = false;
            return result;
        }

        auto uuid_size = this->request_uuid_sizes_.find(domain);
        if (uuid_size == this->request_uuid_sizes_.end() || uuid_size->second == 0) {
            this->authenticator_->ClearSharedSecret(domain);
            this->has_valid_session_info_[domain] = false;
            return ResultCode::SESSION_INFO_HMAC_INVALID;
        }
        result = this->authenticator_->VerifySessionInfoTag(
            domain, this->vin_, this->request_uuids_[domain], uuid_size->second,
            session_info_message, session_info_length, tag, tag_length);
        if (result != ResultCode::SUCCESS) {
            this->authenticator_->ClearSharedSecret(domain);
            this->has_valid_session_info_[domain] = false;
            return result;
        }

        uint32_t now = std::time(nullptr);
        this->clock_times_[domain] = session_info.clock_time;
        this->time_zeros_[domain] = now - session_info.clock_time;
        this->counters_[domain] = session_info.counter;
        memcpy(this->epochs_[domain], session_info.epoch, 16);

        size_t key_size = session_info.publicKey.size;
        if (key_size > sizeof(this->car_keys[domain])) {
            key_size = sizeof(this->car_keys[domain]);
        }
        memcpy(this->car_keys[domain], session_info.publicKey.bytes, key_size);
        this->car_key_sizes[domain] = session_info.publicKey.size;

        this->has_valid_session_info_[domain] = true;
        return ResultCode::SUCCESS;
    }

    int Session::BuildRoutableMessage(UniversalMessage_Domain domain, unsigned char *action_message_buffer,
                                      size_t action_message_buffer_size, unsigned char *output_buffer,
                                      size_t *output_buffer_size) {
        auto valid = this->has_valid_session_info_.find(domain);
        if (valid == this->has_valid_session_info_.end() || !valid->second) {
            return ResultCode::SESSION_INFO_NOT_LOADED;
        }

        UniversalMessage_RoutableMessage routable_message = UniversalMessage_RoutableMessage_init_default;

        UniversalMessage_Destination to_destination = UniversalMessage_Destination_init_default;
        to_destination.sub_destination.domain = domain;
        to_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;

        routable_message.to_destination = to_destination;
        routable_message.has_to_destination = true;

        UniversalMessage_Destination from_destination = UniversalMessage_Destination_init_default;
        memcpy(from_destination.sub_destination.routing_address.bytes, this->routing_address_,
               sizeof(this->routing_address_));
        from_destination.sub_destination.routing_address.size = sizeof(this->routing_address_);
        from_destination.which_sub_destination = UniversalMessage_Destination_routing_address_tag;

        routable_message.from_destination = from_destination;
        routable_message.has_from_destination = true;

        uint32_t counter = this->Counter(domain);
        uint32_t expiresAt = this->ExpiresAt(domain, 10);
        uint32_t flags = 1u << UniversalMessage_Flags_FLAG_ENCRYPT_RESPONSE;
        routable_message.flags = flags;

        this->meta_data_.Start();
        int result_code = this->meta_data_.BuildMetadata(
            domain, Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED, this->vin_,
            expiresAt, counter, this->epochs_[domain], flags);
        if (result_code != ResultCode::SUCCESS) {
            return result_code;
        }

        unsigned char checksum[32];
        this->meta_data_.Checksum(checksum, Signatures_Tag_TAG_END);

        size_t encrypted_output_length = 0;
        unsigned char tag[16];
        unsigned char signed_message_buffer[action_message_buffer_size];

        result_code = this->authenticator_->Encrypt(domain, action_message_buffer,
                                                    action_message_buffer_size,
                                                    checksum, signed_message_buffer,
                                                    sizeof(signed_message_buffer), &encrypted_output_length, tag);
        if (result_code != ResultCode::SUCCESS) {
            return result_code;
        }

        routable_message.which_payload = UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag;
        memcpy(routable_message.payload.protobuf_message_as_bytes.bytes, signed_message_buffer,
               encrypted_output_length);
        routable_message.payload.protobuf_message_as_bytes.size = encrypted_output_length;

        Signatures_SignatureData signature_data = Signatures_SignatureData_init_default;
        Signatures_KeyIdentity signer_identity = Signatures_KeyIdentity_init_default;
        signer_identity.which_identity_type = Signatures_KeyIdentity_public_key_tag;

        this->authenticator_->GetPublicKey(signer_identity.identity_type.public_key.bytes,
                                           &signer_identity.identity_type.public_key.size);

        signature_data.has_signer_identity = true;
        signature_data.signer_identity = signer_identity;

        signature_data.which_sig_type = Signatures_SignatureData_AES_GCM_Personalized_data_tag;
        signature_data.sig_type.AES_GCM_Personalized_data.counter = counter;
        signature_data.sig_type.AES_GCM_Personalized_data.expires_at = expiresAt;

        this->authenticator_->GetNonce(signature_data.sig_type.AES_GCM_Personalized_data.nonce.bytes);
        signature_data.sig_type.AES_GCM_Personalized_data.nonce.size = 12;

        memcpy(signature_data.sig_type.AES_GCM_Personalized_data.epoch.bytes, this->epochs_[domain], 16);
        signature_data.sig_type.AES_GCM_Personalized_data.epoch.size = 16;

        memcpy(signature_data.sig_type.AES_GCM_Personalized_data.tag.bytes, tag, sizeof(tag));
        signature_data.sig_type.AES_GCM_Personalized_data.tag.size = sizeof(tag);

        routable_message.which_sub_sigData = UniversalMessage_RoutableMessage_signature_data_tag;
        routable_message.sub_sigData.signature_data = signature_data;

        return Common::EncodeRoutableMessage(routable_message, output_buffer, output_buffer_size);
    }

    int Session::BuildRequestSessionInfoMessage(UniversalMessage_Domain domain,
                                                unsigned char *output_buffer, size_t *output_length) {
        UniversalMessage_RoutableMessage routable_message = UniversalMessage_RoutableMessage_init_default;

        UniversalMessage_Destination to_destination = UniversalMessage_Destination_init_default;
        to_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
        to_destination.sub_destination.domain = domain;
        // cannot be set to 0 will break the message otherwise
        // to_destination.sub_destination.routing_address.size = 0;

        routable_message.to_destination = to_destination;
        routable_message.has_to_destination = true;

        UniversalMessage_Destination from_destination = UniversalMessage_Destination_init_default;
        from_destination.which_sub_destination = UniversalMessage_Destination_routing_address_tag;
        memcpy(from_destination.sub_destination.routing_address.bytes, this->routing_address_, 16);
        from_destination.sub_destination.routing_address.size = 16;

        routable_message.from_destination = from_destination;
        routable_message.has_from_destination = true;

        UniversalMessage_SessionInfoRequest session_info_request = UniversalMessage_SessionInfoRequest_init_default;

        this->authenticator_->GetPublicKey(session_info_request.public_key.bytes,
                                           &session_info_request.public_key.size);

        routable_message.payload.session_info_request = session_info_request;
        routable_message.which_payload = UniversalMessage_RoutableMessage_session_info_request_tag;

        Common::GenerateUUID(routable_message.uuid.bytes, &routable_message.uuid.size);
        this->SetRequestUuid(domain, routable_message.uuid.bytes, routable_message.uuid.size);

        return Common::EncodeRoutableMessage(routable_message, output_buffer, output_length);
    }
} // TeslaBLE
