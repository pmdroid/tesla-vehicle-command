#include "ble.h"

#include <shared.h>
#include <iostream>
#include <mbedtls/sha1.h>
#include <simpleble/Adapter.h>

#include "pb_decode.h"

auto CAR_SERVICE_UUID = "00000211-b2d1-43f0-9b88-960cebf8b91e";
auto CAR_WRITE_CHAR_UUID = "00000212-b2d1-43f0-9b88-960cebf8b91e";
auto CAR_READ_CHAR_UUID = "00000213-b2d1-43f0-9b88-960cebf8b91e";

namespace TeslaBLE {
    void BLE::handleMessage(std::vector<unsigned char> message) {
        if (this->debug_enabled) {
            TeslaBLE::Common::DumpHexBuffer("RX: ", message.data(), message.size());
        }

        UniversalMessage_RoutableMessage output_message = UniversalMessage_RoutableMessage_init_zero;
        Common::DecodeRoutableMessage(message.data(), message.size(), &output_message);

        current_message_size = 0;
        this->message_buffer.clear();
        this->message_buffer.resize(0);
        this->message_buffer.shrink_to_fit();

        this->message_handler(output_message);
    }

    void BLE::callback(SimpleBLE::ByteArray payload) {
        pb_byte_t input_buffer[payload.size()];
        memcpy(input_buffer, payload.data(), payload.size());

        const size_t size = TeslaBLE::Common::ExtractLength(input_buffer);
        if (current_message_size == 0 && size > payload.size()) {
            message_buffer.clear();
            message_buffer.resize(size);
            message_buffer.shrink_to_fit();
            current_message_size = 0;

            size_t payload_size = payload.size() - 2;
            memcpy(message_buffer.data(), input_buffer + 2, payload_size);
            current_message_size = payload_size;
            return;
        }

        if (current_message_size > 0) {
            memcpy(message_buffer.data() + current_message_size, input_buffer, payload.size());
            current_message_size = current_message_size + payload.size();
            this->handleMessage(message_buffer);
            return;
        }

        message_buffer.clear();
        message_buffer.resize(size);
        message_buffer.shrink_to_fit();
        current_message_size = 0;

        size_t payload_size = payload.size() - 2;
        memcpy(message_buffer.data(), input_buffer + 2, payload_size);
        this->handleMessage(message_buffer);
    }

    int BLE::connect(unsigned char *vin) {
        const auto adapters = SimpleBLE::Adapter::get_adapters();
        auto adapter = adapters[0];

        printf("Using adapter MAC: %s\n", adapter.address().c_str());

        char identifier[21];
        int result = TeslaBLE::Common::calculateIdentifier(vin, identifier);
        if (result != ResultCode::SUCCESS) {
            return result;
        }

        printf("Connecting to Tesla (%s)...\n", identifier);
        adapter.scan_for(5000);
        auto peripherals = adapter.scan_get_results();

        for (auto peripheral: peripherals) {
            if (peripheral.identifier() == identifier) {
                peripheral.connect();
                printf("Found Tesla \"%s\"\n", peripheral.identifier().c_str());
                printf("MAC: %s", peripheral.address().c_str());
                peripheral.indicate(CAR_SERVICE_UUID, CAR_READ_CHAR_UUID, [this](SimpleBLE::ByteArray payload) {
                    this->callback(payload);
                });
                this->peripheral = peripheral;
                return 0;
            }
        }

        printf("Found Tesla not found \"%s\"\n", identifier);
        return 1;
    }

    void BLE::registerMessageHandler(std::function<void(UniversalMessage_RoutableMessage)> message_handler) {
        this->message_handler = std::move(message_handler);
    }

    void BLE::send(char *buffer, size_t buffer_size) {
        SimpleBLE::ByteArray payload = SimpleBLE::ByteArray((char *) buffer, buffer_size);
        this->peripheral.write_request(CAR_SERVICE_UUID, CAR_WRITE_CHAR_UUID, payload);
    }

    void BLE::close() {
        this->peripheral.unsubscribe(CAR_SERVICE_UUID, CAR_READ_CHAR_UUID);
        this->peripheral.disconnect();
    }
} // TeslaBLE
