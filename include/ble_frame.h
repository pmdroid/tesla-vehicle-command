#ifndef TESLA_BLE_FRAME_H
#define TESLA_BLE_FRAME_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace TeslaBLE {
    class BleFrame {
        std::vector<uint8_t> buffer_;
        size_t expected_ = 0;

    public:
        enum Status {
            NEED_MORE = 0,
            COMPLETE = 1,
            ERROR = 2,
        };

        Status Add(const uint8_t *data, size_t length);
        const uint8_t *Payload() const;
        size_t PayloadSize() const;
        void Reset();
    };
}

#endif
