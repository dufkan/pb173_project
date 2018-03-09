#include "impl.hpp"

void pad(std::vector<uint8_t>& data) {
    uint8_t val = 16 - (data.size() % 16);
    for(uint8_t i = 0; i < val; ++i)
        data.push_back(val);
}

void unpad(std::vector<uint8_t>& data) {
    if(data.size() < 16) return;
    uint8_t val = data[data.size() - 1];
    if(val > 16) return;
    data.resize(data.size() - val);
}

std::vector<uint8_t> encrypt_aes(const std::vector<uint8_t>& data, std::array<uint8_t, 16> iv, const std::array<uint8_t, 16>& key) {
    std::vector<uint8_t> result;
    result.resize(data.size());

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key.data(), 128);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, data.size(), iv.data(), data.data(), result.data());
    mbedtls_aes_free(&ctx);

    return result;
}

std::vector<uint8_t> encrypt(std::vector<uint8_t> data, const std::array<uint8_t, 16>& iv, const std::array<uint8_t, 16>& key) {
    pad(data);
    std::vector<uint8_t> plainhash = hash(data);

    std::vector<uint8_t> ciphertext = encrypt_aes(data, iv, key);
    ciphertext.insert(ciphertext.end(), plainhash.begin(), plainhash.end());

    std::vector<uint8_t> cipherhash = hash(ciphertext);
    ciphertext.insert(ciphertext.end(), cipherhash.begin(), cipherhash.end());

    return ciphertext;
}

std::vector<uint8_t> decrypt_aes(const std::vector<uint8_t>& data, std::array<uint8_t, 16> iv, const std::array<uint8_t, 16>& key) {
    std::vector<uint8_t> result;
    result.resize(data.size());

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, key.data(), 128);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, data.size(), iv.data(), data.data(), result.data());
    mbedtls_aes_free(&ctx);

    return result;
}

std::vector<uint8_t> decrypt(std::vector<uint8_t> data, const std::array<uint8_t, 16>& iv, const std::array<uint8_t, 16>& key) {

    std::vector<uint8_t> cipherhash{data.end() - 64, data.end()};
    data.resize(data.size() - 64);

    if(cipherhash != hash(data)) {
        throw crypto_exception("Integrity fail.");
    }

    std::vector<uint8_t> plainhash{data.end() - 64, data.end()};
    data.resize(data.size() - 64);

    std::vector<uint8_t> plaintext = decrypt_aes(data, iv, key);

    if(plainhash != hash(plaintext)) {
        throw crypto_exception("Key fail.");
    }

    std::vector<uint8_t> result = decrypt_aes(data, iv, key);
    unpad(result);

    return result;
}

std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result{};
    result.resize(64);

    mbedtls_sha512_ret(data.data(), data.size(), result.data(), 0);

    return result;
}

std::vector<uint8_t> read_file(const std::string& fname) {
    std::ifstream ifs{fname, std::ios::binary};
    if(!ifs.is_open())
        throw std::ios_base::failure{"File " + fname + " couldn't be opened for reading."};
    ifs >> std::noskipws;
    return std::vector<uint8_t>{std::istream_iterator<uint8_t>{ifs}, std::istream_iterator<uint8_t>{}};
}

void write_file(const std::string& fname, const std::vector<uint8_t>& data, bool append) {
    std::ofstream ofs{fname, std::ios::binary | (append ? std::ios::app : std::ios::trunc)};
    if(!ofs.is_open())
        throw std::ios_base::failure{"File " + fname + "couldn't be opened for writing."};
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
}

std::array<uint8_t, 16> parse_key(const std::string& input) {
    if(input.length() != 32) {
        throw std::invalid_argument{"Invalid key!"};
    }

    std::array<uint8_t, 16> key;
    for(size_t i = 0; i < 16; ++i) {
        std::string byte = input.substr(i * 2, 2);
        key[i] = static_cast<uint8_t>(std::strtoul(byte.c_str(), nullptr, 16));
    }

    return key;
}

void encrypt_file(const std::string& infile, const std::string& outfile, const std::array<uint8_t, 16>& iv, const std::array<uint8_t, 16>& key) {
    write_file(outfile, encrypt(read_file(infile), iv, key));
}

void decrypt_file(const std::string& infile, const std::string& outfile, const std::array<uint8_t, 16>& iv, const std::array<uint8_t, 16>& key) {
    write_file(outfile, decrypt(read_file(infile), iv, key));
}
