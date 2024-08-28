/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#include "shared.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <mbedtls/error.h>
#include <mbedtls/sha1.h>

#include <universal_message.pb.h>
#include <vcsec.pb.h>

#include <pb_decode.h>
#include <pb_encode.h>

namespace TeslaBLE {
    unsigned char *Common::HexStrToUint8(const char *input) {
        if (input == NULL)
            return NULL;

        size_t slength = strlen(input);
        if ((slength % 2) != 0) // must be even
            return NULL;

        size_t dlength = slength / 2;
        uint8_t *data = (uint8_t *) malloc(dlength);
        memset(data, 0, dlength);
        size_t index = 0;

        while (index < slength) {
            char c = input[index];
            int value = 0;
            if (c >= '0' && c <= '9')
                value = (c - '0');
            else if (c >= 'A' && c <= 'F')
                value = (10 + (c - 'A'));
            else if (c >= 'a' && c <= 'f')
                value = (10 + (c - 'a'));
            else
                return NULL;

            data[(index / 2)] += value << (((index + 1) % 2) * 4);
            index++;
        }

        return data;
    }

    void Common::DumpHexBuffer(const char *title, unsigned char *buffer, size_t size) {
        size_t i = 0;
        printf("%s", title);
        for (i = 0; i < size; i++) {
            printf("%c%c", "0123456789ABCDEF"[buffer[i] / 16],
                   "0123456789ABCDEF"[buffer[i] % 16]);
        }
        printf("\n");
    }

    void Common::PrependLength(unsigned char *input_buffer, size_t input_buffer_length, unsigned char *output_buffer,
                               size_t *output_buffer_size) {
        uint8_t higher_byte = input_buffer_length >> 8;
        uint8_t lower_byte = input_buffer_length & 0xFF;

        uint8_t temp_buffer[2];
        temp_buffer[0] = higher_byte;
        temp_buffer[1] = lower_byte;

        memcpy(output_buffer, temp_buffer, sizeof(temp_buffer));
        memcpy(output_buffer + 2, input_buffer, input_buffer_length);
        *output_buffer_size = input_buffer_length + 2;
    }

    int Common::calculateIdentifier(unsigned char *vin, char *output) {
        unsigned char parsed_vin[18];
        strcpy((char *) parsed_vin, (char *) vin);

        unsigned char hashed_vin[20];
        const int return_code = mbedtls_sha1(parsed_vin, 17, hashed_vin);
        if (return_code != 0) {
            Common::PrintErrorFromMbedTlsErrorCode(return_code);
            return 1;
        }

        output[0] = 'S';
        for (int i = 0; i < 8; ++i) {
            sprintf(&output[1 + i * 2], "%02x", hashed_vin[i]);
        }
        output[17] = 'C';
        output[18] = '\0';

        return 0;
    }

    size_t Common::ExtractLength(unsigned char *output_buffer) {
        uint16_t length = (static_cast<uint16_t>(output_buffer[0]) << 8) | static_cast<uint16_t>(output_buffer[1]);
        return length;
    }

    void Common::GenerateUUID(unsigned char *output_buffer, uint16_t *output_size) {
        unsigned char uuid[16];
        for (int i = 0; i < sizeof(uuid); i++) {
            uuid[i] = rand() % 256;
        }
        memcpy(output_buffer, uuid, sizeof(uuid));
        *output_size = sizeof(uuid);
    }

    int Common::DecodeRoutableMessage(unsigned char *buffer, size_t buffer_size,
                                      UniversalMessage_RoutableMessage *output_message) {
        pb_istream_t input_stream = pb_istream_from_buffer(buffer, buffer_size);
        if (!pb_decode(&input_stream, UniversalMessage_RoutableMessage_fields, output_message)) {
            printf("Decoding failed: %s\n", PB_GET_ERROR(&input_stream));
            return ResultCode::NANOPB_DECODE_ERROR;
        }

        return ResultCode::SUCCESS;
    }

    int Common::DecodeFromVCSECMessage(unsigned char *buffer, size_t buffer_size,
                                       VCSEC_FromVCSECMessage *output_message) {
        pb_istream_t input_stream = pb_istream_from_buffer(buffer, buffer_size);
        if (!pb_decode(&input_stream, VCSEC_FromVCSECMessage_fields, output_message)) {
            printf("Decoding failed: %s\n", PB_GET_ERROR(&input_stream));
            return ResultCode::NANOPB_DECODE_ERROR;
        }

        return ResultCode::SUCCESS;
    }

    int Common::EncodeRoutableMessage(UniversalMessage_RoutableMessage routable_message,
                                      unsigned char *output_buffer,
                                      size_t *output_size) {
        Common::GenerateUUID(routable_message.uuid.bytes, &routable_message.uuid.size);

        pb_ostream_t size_stream = {nullptr};
        if (!pb_encode(&size_stream, UniversalMessage_RoutableMessage_fields, &routable_message)) {
            printf("Failed to encode message: %s", PB_GET_ERROR(&size_stream));
            return ResultCode::NANOPB_ENCODE_ERROR;
        }

        uint8_t message_buffer[size_stream.bytes_written];
        pb_ostream_t message_stream = pb_ostream_from_buffer(message_buffer, size_stream.bytes_written);
        if (!pb_encode(&message_stream, UniversalMessage_RoutableMessage_fields, &routable_message)) {
            printf("Failed to encode message: %s", PB_GET_ERROR(&message_stream));
            return ResultCode::NANOPB_ENCODE_ERROR;
        }

        Common::PrependLength(message_buffer, message_stream.bytes_written, output_buffer, output_size);
        return ResultCode::SUCCESS;
    }

    void Common::ResultCodeToMessage(int result_code) {
        if (result_code == ResultCode::ERROR) {
            printf("General error.\n");
        } else if (result_code == ResultCode::MBEDTLS_ERROR) {
            printf("mbedtls error.\n");
        } else if (result_code == ResultCode::TAG_OUT_OF_ORDER) {
            printf("The provided metadata tag is out of order.\n");
        } else if (result_code == ResultCode::TAG_VALUE_EMPTY) {
            printf("The provided metadata value is empty.\n");
        } else if (result_code == ResultCode::TAG_VALUE_TOO_LONG) {
            printf("The provided metadata value is too long.\n");
        } else if (result_code == ResultCode::NANOPB_DECODE_ERROR) {
            printf("Failed to decode protobuf message.\n");
        } else if (result_code == ResultCode::NANOPB_ENCODE_ERROR) {
            printf("Failed to encode protobuf message.\n");
        } else if (result_code == ResultCode::PRIVATE_KEY_NOT_LOADED) {
            printf("Private key has not been loaded yet.\n");
        } else if (result_code == ResultCode::SESSION_INFO_NOT_LOADED) {
            printf("Session info has not been loaded yet.\n");
        } else {
            printf("Unkown result code.\n");
        }
    }

    void Common::ErrorCodeToMessage(UniversalMessage_MessageFault_E message_fault) {
        if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE) {
            printf("Request succeeded.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_BUSY) {
            printf("Required vehicle subsystem is busy. Try again.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_TIMEOUT) {
            printf("Vehicle subsystem did not respond. Try again.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_UNKNOWN_KEY_ID) {
            printf(
                "Vehicle did not recognize the key used to authorize command. Make sure your key is paired with the vehicle.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INACTIVE_KEY) {
            printf("Key used to authorize command has been disabled.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_SIGNATURE) {
            printf("Command signature/MAC is incorrect. Use included session info to update session and try again.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER) {
            printf(
                "Command anti-replay counter has been used before. Use included session info to update session and try again.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INSUFFICIENT_PRIVILEGES) {
            printf(
                "User is not authorized to execute command. This can be because of the role or because of vehicle state.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_DOMAINS) {
            printf(
                "Command was malformed or addressed to an unrecognized vehicle system. May indicate client error or older vehicle firmware.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_COMMAND) {
            printf("Unrecognized command. May indicate client error or unsupported vehicle firmware.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_DECODING) {
            printf("Could not parse command. Indicates client error.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INTERNAL) {
            printf(
                "Internal vehicle error. Try again. Most commonly encountered when the vehicle has not finished booting.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_WRONG_PERSONALIZATION) {
            printf("Command sent to wrong VIN.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_BAD_PARAMETER) {
            printf("Command was malformed or used a deprecated parameter.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_KEYCHAIN_IS_FULL) {
            printf("Vehicle's keychain is full. You must delete a key before you can add another.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INCORRECT_EPOCH) {
            printf("Session ID mismatch. Use included session info to update session and try again.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_IV_INCORRECT_LENGTH) {
            printf(
                "Initialization Value length is incorrect (AES-GCM must use 12-byte IVs). Indicates a client programming error.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_TIME_EXPIRED) {
            printf(
                "Command expired. Use included session info to determine if clocks have desynchronized and try again.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NOT_PROVISIONED_WITH_IDENTITY) {
            printf("Vehicle has not been provisioned with a VIN and may require service.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_COULD_NOT_HASH_METADATA) {
            printf("Internal vehicle error.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_TIME_TO_LIVE_TOO_LONG) {
            printf(
                "Vehicle rejected command because its expiration time was too far in the future. This is a security precaution.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_REMOTE_ACCESS_DISABLED) {
            printf("The vehicle owner has disabled Mobile access.\n");
        } else if (message_fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_REMOTE_SERVICE_ACCESS_DISABLED) {
            printf(
                "The command was authorized with a Service key, but the vehicle has not been configured to permit remote service commands.\n");
        } else if (message_fault ==
                   UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_COMMAND_REQUIRES_ACCOUNT_CREDENTIALS) {
            printf(
                "The command requires proof of Tesla account credentials but was not sent over a channel that provides this proof. Resend the command using Fleet API.\n");
        } else {
            printf("Unkown fault message");
        }
    }

    void Common::OperationStatusToMessage(UniversalMessage_OperationStatus_E operation_status) {
        if (operation_status == UniversalMessage_OperationStatus_E_OPERATIONSTATUS_OK) {
            printf("Operation status ok\n");
        } else if (operation_status == UniversalMessage_OperationStatus_E_OPERATIONSTATUS_WAIT) {
            printf("Operation status wait (Might be user interaction, like tap NFC card)\n");
        } else if (operation_status == UniversalMessage_OperationStatus_E_OPERATIONSTATUS_ERROR) {
            printf("Operation status error\n");
        } else {
            printf("Unkown operation status");
        }
    }

    void Common::PrintErrorFromMbedTlsErrorCode(int result) {
        char error_buf[200];
        mbedtls_strerror(result, error_buf, 200);
        printf("mbedtls error: -0x%04x - %s\n", (unsigned int) -result, error_buf);
    }
}
