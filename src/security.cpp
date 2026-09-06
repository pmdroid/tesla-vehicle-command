/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#include "security.h"

#include <cstdio>
#include <cstring>

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

    int Security::BuildRkeAction(VCSEC_RKEAction_E action, unsigned char *buffer, size_t *buffer_size) {
        VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_zero;
        unsigned_message.which_sub_message = VCSEC_UnsignedMessage_RKEAction_tag;
        unsigned_message.sub_message.RKEAction = action;
        return Security::BuildUnsignedMessage(&unsigned_message, buffer, buffer_size);
    }

    int Security::BuildClosureMove(VCSEC_ClosureMoveType_E rear_trunk, VCSEC_ClosureMoveType_E front_trunk,
                                   VCSEC_ClosureMoveType_E tonneau, unsigned char *buffer, size_t *buffer_size) {
        VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_zero;
        unsigned_message.which_sub_message = VCSEC_UnsignedMessage_closureMoveRequest_tag;
        unsigned_message.sub_message.closureMoveRequest.rearTrunk = rear_trunk;
        unsigned_message.sub_message.closureMoveRequest.frontTrunk = front_trunk;
        unsigned_message.sub_message.closureMoveRequest.tonneau = tonneau;
        return Security::BuildUnsignedMessage(&unsigned_message, buffer, buffer_size);
    }

    int Security::Unlock(unsigned char *buffer, size_t *buffer_size) {
        return Security::BuildRkeAction(VCSEC_RKEAction_E_RKE_ACTION_UNLOCK, buffer, buffer_size);
    }

    int Security::Lock(unsigned char *buffer, size_t *buffer_size) {
        return Security::BuildRkeAction(VCSEC_RKEAction_E_RKE_ACTION_LOCK, buffer, buffer_size);
    }

    int Security::Wake(unsigned char *buffer, size_t *buffer_size) {
        return Security::BuildRkeAction(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, buffer, buffer_size);
    }

    int Security::AutoSecure(unsigned char *buffer, size_t *buffer_size) {
        return Security::BuildRkeAction(VCSEC_RKEAction_E_RKE_ACTION_AUTO_SECURE_VEHICLE, buffer, buffer_size);
    }

    int Security::RemoteDrive(unsigned char *buffer, size_t *buffer_size) {
        return Security::BuildRkeAction(VCSEC_RKEAction_E_RKE_ACTION_REMOTE_DRIVE, buffer, buffer_size);
    }

    int Security::OpenTrunk(unsigned char *buffer, size_t *buffer_size) {
        return Security::BuildClosureMove(VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_MOVE,
                                          VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE,
                                          VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE, buffer, buffer_size);
    }

    int Security::CloseTrunk(unsigned char *buffer, size_t *buffer_size) {
        return Security::BuildClosureMove(VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE,
                                          VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE,
                                          VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE, buffer, buffer_size);
    }

    int Security::OpenFrunk(unsigned char *buffer, size_t *buffer_size) {
        return Security::BuildClosureMove(VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE,
                                          VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_MOVE,
                                          VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE, buffer, buffer_size);
    }

    int Security::OpenTonneau(unsigned char *buffer, size_t *buffer_size) {
        return Security::BuildClosureMove(VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE,
                                          VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE,
                                          VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN, buffer, buffer_size);
    }

    int Security::CloseTonneau(unsigned char *buffer, size_t *buffer_size) {
        return Security::BuildClosureMove(VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE,
                                          VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE,
                                          VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE, buffer, buffer_size);
    }

    int Security::StopTonneau(unsigned char *buffer, size_t *buffer_size) {
        return Security::BuildClosureMove(VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE,
                                          VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE,
                                          VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_STOP, buffer, buffer_size);
    }

    int Security::GetStatus(unsigned char *buffer, size_t *buffer_size) {
        VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_zero;
        unsigned_message.which_sub_message = VCSEC_UnsignedMessage_InformationRequest_tag;
        unsigned_message.sub_message.InformationRequest.informationRequestType =
            VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS;
        return Security::BuildUnsignedMessage(&unsigned_message, buffer, buffer_size);
    }

    int Security::GetWhitelistInfo(unsigned char *buffer, size_t *buffer_size) {
        VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_zero;
        unsigned_message.which_sub_message = VCSEC_UnsignedMessage_InformationRequest_tag;
        unsigned_message.sub_message.InformationRequest.informationRequestType =
            VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO;
        return Security::BuildUnsignedMessage(&unsigned_message, buffer, buffer_size);
    }

    int Security::GetWhitelistEntryInfo(uint32_t slot, unsigned char *buffer, size_t *buffer_size) {
        VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_zero;
        unsigned_message.which_sub_message = VCSEC_UnsignedMessage_InformationRequest_tag;
        unsigned_message.sub_message.InformationRequest.informationRequestType =
            VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_ENTRY_INFO;
        unsigned_message.sub_message.InformationRequest.which_key = VCSEC_InformationRequest_slot_tag;
        unsigned_message.sub_message.InformationRequest.key.slot = slot;
        return Security::BuildUnsignedMessage(&unsigned_message, buffer, buffer_size);
    }

    int Security::RemoveKey(const unsigned char *public_key, size_t public_key_size, unsigned char *buffer,
                            size_t *buffer_size) {
        if (public_key == nullptr || public_key_size == 0 ||
            public_key_size > sizeof(VCSEC_PublicKey_PublicKeyRaw_t().bytes)) {
            return ResultCode::ERROR;
        }

        VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_zero;
        unsigned_message.which_sub_message = VCSEC_UnsignedMessage_WhitelistOperation_tag;
        unsigned_message.sub_message.WhitelistOperation.which_sub_message =
            VCSEC_WhitelistOperation_removePublicKeyFromWhitelist_tag;
        memcpy(unsigned_message.sub_message.WhitelistOperation.sub_message.removePublicKeyFromWhitelist.PublicKeyRaw
                   .bytes,
               public_key, public_key_size);
        unsigned_message.sub_message.WhitelistOperation.sub_message.removePublicKeyFromWhitelist.PublicKeyRaw.size =
            public_key_size;
        return Security::BuildUnsignedMessage(&unsigned_message, buffer, buffer_size);
    }
} // TeslaBLE
