/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#ifndef TESLA_BLE_SHARED_H
#define TESLA_BLE_SHARED_H

#include <cstdint>
#include <cstddef>

#include <universal_message.pb.h>
#include <vcsec.pb.h>

#include <shared.h>


enum ResultCode : int {
    SUCCESS = 0,
    ERROR = 1,
    TAG_OUT_OF_ORDER = 10,
    TAG_VALUE_EMPTY = 11,
    TAG_VALUE_TOO_LONG = 12,
    MBEDTLS_ERROR = 20,
    NANOPB_ENCODE_ERROR = 30,
    NANOPB_DECODE_ERROR = 31,
    PRIVATE_KEY_NOT_LOADED = 40,
    SESSION_INFO_NOT_LOADED = 50,
    SESSION_INFO_KEY_NOT_WHITELISTED = 51,
};

namespace TeslaBLE {
    class Common {
    public:
        static unsigned char *HexStrToUint8(const char *string);

        static void DumpHexBuffer(const char *title, unsigned char *buf, size_t len);

        // static void ParseVIN(const std::string &vin, char *buffer);

        static void PrependLength(unsigned char *input_buffer, size_t input_buffer_length, unsigned char *output_buffer,
                                  size_t *output_buffer_size);

        static int calculateIdentifier(unsigned char *vin, char *output);

        static size_t ExtractLength(unsigned char *input_buffer);

        static void GenerateUUID(unsigned char *output_buffer, uint16_t *output_size);

        static int DecodeRoutableMessage(unsigned char *buffer, size_t buffer_size,
                                         UniversalMessage_RoutableMessage *output_message);

        static int DecodeFromVCSECMessage(unsigned char *buffer, size_t buffer_size,
                                          VCSEC_FromVCSECMessage *output_message);

        static int EncodeRoutableMessage(UniversalMessage_RoutableMessage routable_message,
                                         unsigned char *output_buffer,
                                         size_t *output_size);

        static void ResultCodeToMessage(int result_code);

        static void ErrorCodeToMessage(UniversalMessage_MessageFault_E message_fault);

        static void OperationStatusToMessage(UniversalMessage_OperationStatus_E operation_status);

        static void PrintErrorFromMbedTlsErrorCode(int result);
    };
}


#endif //TESLA_BLE_SHARED_H
