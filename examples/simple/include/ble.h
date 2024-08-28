#ifndef BLE_H
#define BLE_H

#include <functional>
#include <universal_message.pb.h>
#include <simpleble/Adapter.h>
#include <simpleble/Peripheral.h>

namespace TeslaBLE {
    class BLE {
    private:
        size_t MAX_MESSAGE_SIZE = 1024;
        size_t current_message_size = 0;
        std::vector<unsigned char> message_buffer;
        std::function<void(UniversalMessage_RoutableMessage routable_message)> message_handler;
        SimpleBLE::Peripheral peripheral;
        bool debug_enabled = false;

        void handleMessage(std::vector<unsigned char> message);

        void callback(SimpleBLE::ByteArray payload);

    public:
        explicit BLE(bool debug_enabled) {
            this->debug_enabled = debug_enabled;
        }

        SimpleBLE::Peripheral search(const unsigned char *vin);

        int connect(unsigned char *vin);

        void registerMessageHandler(std::function<void(UniversalMessage_RoutableMessage)> message_handler);

        void send(char *buffer, size_t buffer_size);

        void close();
    };
} // TeslaBLE

#endif //BLE_H
