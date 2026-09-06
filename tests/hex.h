#ifndef TESLA_BLE_TEST_HEX_H
#define TESLA_BLE_TEST_HEX_H

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

inline int HexNibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    throw std::invalid_argument("invalid hex");
}

inline std::vector<uint8_t> ParseHex(const std::string &hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("odd hex length");
    }
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); i++) {
        out[i] = static_cast<uint8_t>((HexNibble(hex[i * 2]) << 4) | HexNibble(hex[i * 2 + 1]));
    }
    return out;
}

#endif
