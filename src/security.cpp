/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#include "security.h"

#include <cstdio>

#include <vcsec.pb.h>

#include <pb.h>
#include <pb_encode.h>
#include <shared.h>

namespace TeslaBLE {
    int Security::BuildUnsignedMessage(const VCSEC_UnsignedMessage *unsigned_message, unsigned char *buffer,
                                       size_t *buffer_size) {
        pb_ostream_t size_stream = {nullptr};
        if (!pb_encode(&size_stream, VCSEC_UnsignedMessage_fields, unsigned_message)) {
            printf("Failed to encode message: %s", PB_GET_ERROR(&size_stream));
            return ResultCode::NANOPB_ENCODE_ERROR;
        }

        pb_ostream_t stream = pb_ostream_from_buffer(buffer, size_stream.bytes_written);
        if (!pb_encode(&stream, VCSEC_UnsignedMessage_fields, unsigned_message)) {
            printf("Failed to encode message: %s", PB_GET_ERROR(&stream));
            return ResultCode::NANOPB_ENCODE_ERROR;
        }

        *buffer_size = stream.bytes_written;
        return ResultCode::SUCCESS;
    }

    int Security::Unlock(unsigned char *buffer, size_t *buffer_size) {
        VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage{};
        unsigned_message.sub_message.RKEAction = VCSEC_RKEAction_E_RKE_ACTION_UNLOCK;
        unsigned_message.which_sub_message = VCSEC_UnsignedMessage_RKEAction_tag;
        return Security::BuildUnsignedMessage(&unsigned_message, buffer, buffer_size);
    }

    int Security::Lock(unsigned char *buffer, size_t *buffer_size) {
        VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage{};
        unsigned_message.sub_message.RKEAction = VCSEC_RKEAction_E_RKE_ACTION_LOCK;
        unsigned_message.which_sub_message = VCSEC_UnsignedMessage_RKEAction_tag;
        return Security::BuildUnsignedMessage(&unsigned_message, buffer, buffer_size);
    }

    int Security::Wake(unsigned char *buffer, size_t *buffer_size) {
        VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage{};
        unsigned_message.sub_message.RKEAction = VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE;
        unsigned_message.which_sub_message = VCSEC_UnsignedMessage_RKEAction_tag;
        return Security::BuildUnsignedMessage(&unsigned_message, buffer, buffer_size);
    }
} // TeslaBLE
