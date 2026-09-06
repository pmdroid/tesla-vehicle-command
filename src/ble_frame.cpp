#include <ble_frame.h>

#include <shared.h>

namespace TeslaBLE {
    BleFrame::Status BleFrame::Add(const uint8_t *data, size_t length) {
        if (data == nullptr || length == 0) {
            return ERROR;
        }

        if (expected_ == 0) {
            if (length < 2) {
                return ERROR;
            }
            expected_ = Common::ExtractLength(const_cast<unsigned char *>(data));
            if (expected_ == 0) {
                return ERROR;
            }
            buffer_.clear();
            const size_t chunk = length - 2;
            if (chunk > expected_) {
                Reset();
                return ERROR;
            }
            buffer_.insert(buffer_.end(), data + 2, data + length);
            if (buffer_.size() == expected_) {
                return COMPLETE;
            }
            return NEED_MORE;
        }

        if (buffer_.size() + length > expected_) {
            Reset();
            return ERROR;
        }
        buffer_.insert(buffer_.end(), data, data + length);
        if (buffer_.size() == expected_) {
            return COMPLETE;
        }
        return NEED_MORE;
    }

    const uint8_t *BleFrame::Payload() const {
        return buffer_.data();
    }

    size_t BleFrame::PayloadSize() const {
        return buffer_.size();
    }

    void BleFrame::Reset() {
        buffer_.clear();
        expected_ = 0;
    }
}
