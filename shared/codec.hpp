#ifndef CODEC_HPP
#define CODEC_HPP
#include <vector>
#include <cstdint>
#include <stdexcept>

class Encoder {
    std::vector<uint8_t> data;

public:
    void put(uint8_t val) {
        data.push_back(val);
    }

    void put(uint16_t val) {
        data.push_back(val >> 8 & 0xff);
        data.push_back(val & 0xff);
    }

    void put(uint32_t val) {
        data.push_back(val >> 24 & 0xff);
        data.push_back(val >> 16 & 0xff);
        data.push_back(val >> 8 & 0xff);
        data.push_back(val & 0xff);
    }

    void put(const std::vector<uint8_t>& val) {
        data.insert(std::end(data), std::begin(val), std::end(val));
    }

    void put(const std::string& val) {
        data.insert(std::end(data), std::begin(val), std::end(val));
    }

    std::vector<uint8_t> get() {
        return std::move(data);
    }

    void reserve(size_t len) {
        data.reserve(len);
    }
};

class Decoder {
    std::vector<uint8_t> data;
    size_t i = 0;

    void check_read(size_t len) {
        if (i + len > data.size())
            throw std::out_of_range("Accessing element out of bounds.");
    }

public:

    Decoder(std::vector<uint8_t> data): data(data) {}

    uint8_t get_u8() {
        check_read(1);
        return data[i++];
    }

    uint16_t get_u16() {
        check_read(2);
        uint16_t result = data[i++] << 8;
        result |= data[i++];
        return result;
    }

    uint32_t get_u32() {
        check_read(4);
        uint32_t result = data[i++] << 24;
        result |= data[i++] << 16;
        result |= data[i++] << 8;
        result |= data[i++];
        return result;
    }

    std::vector<uint8_t> get_vec(size_t len) {
        check_read(len);
        i += len;
        return std::vector<uint8_t>{data.begin() + (i - len), data.begin() + i};
    }

    std::string get_str(size_t len) {
        check_read(len);
        i += len;
        return std::string{reinterpret_cast<const char*>(data.data() + (i - len)), len};
    }
};

#endif
