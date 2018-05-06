#ifndef CODEC_HPP
#define CODEC_HPP
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <algorithm>

class Encoder {
#ifdef TESTMODE
public:
#endif
    std::vector<uint8_t> data;

public:
    void put(bool val) {
        data.push_back(static_cast<uint8_t>(val ? 1 : 0));
    }

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

    template<size_t N>
    void put(const std::array<uint8_t, N>& val) {
        data.insert(std::end(data), std::begin(val), std::end(val));
    }

    void put(const uint8_t* val, size_t len) {
        data.insert(std::end(data), val, val + len);
    }

    std::vector<uint8_t> move() {
        return std::move(data);
    }

    const std::vector<uint8_t>& get() const {
        return std::move(data);
    }

    void reserve(size_t len) {
        data.reserve(len);
    }
};

template<typename C>
class TDecoder {
#ifdef TESTMODE
public:
#endif
    C data; // TODO swap for cyclic buffer or some better data structure
    size_t i = 0;

    void check_read(size_t len) {
        if (i + len > data.size())
            throw std::out_of_range("Accessing element out of bounds.");
    }

public:
    TDecoder() = default;
    TDecoder(C data): data(data) {}

    void append(const std::vector<uint8_t>& new_data) {
        data.insert(std::end(data), std::begin(new_data), std::end(new_data));
    }

    void append(const uint8_t* new_data, size_t len) {
        data.insert(std::end(data), new_data, new_data + len);
    }

    void cut() {
        data.erase(std::begin(data), std::begin(data) + i);
        i = 0;
    }

    bool get_bool() {
        check_read(1);
        return data[i++] == 1;
    }

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

    inline std::vector<uint8_t> get_vec() {
        return get_vec(data.size() - i);
    }

    template<size_t N>
    std::array<uint8_t, N> get_arr() {
        std::array<uint8_t, N> arr;
        std::copy(data.data() + i, data.data() + i + N, arr.data());
        i += N;
        return arr;
    }

    std::string get_str(size_t len) {
        check_read(len);
        i += len;
        return std::string{reinterpret_cast<const char*>(data.data() + (i - len)), len};
    }

    size_t size() {
        return data.size() - i;
    }
};

using Decoder = TDecoder<std::vector<uint8_t>>;
using RefDecoder = TDecoder<std::vector<uint8_t>&>;

#endif
