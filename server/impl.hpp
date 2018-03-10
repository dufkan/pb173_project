#ifndef IMPL_HPP
#define IMPL_HPP

#include <array>
#include <vector>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <iostream>
#include <exception>

#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"

class crypto_exception : public std::runtime_error {
public:
    crypto_exception(std::string msg): std::runtime_error(msg) {}
};


void pad(std::vector<uint8_t>& data);
void unpad(std::vector<uint8_t>& data);

std::vector<uint8_t> encrypt_aes(const std::vector<uint8_t>& data, std::array<uint8_t, 16> iv, const std::array<uint8_t, 16>& key);
std::vector<uint8_t> decrypt_aes(const std::vector<uint8_t>& data, std::array<uint8_t, 16> iv, const std::array<uint8_t, 16>& key);

std::vector<uint8_t> encrypt(std::vector<uint8_t> data, const std::array<uint8_t, 16>& iv, const std::array<uint8_t, 16>& key);
std::vector<uint8_t> decrypt(std::vector<uint8_t> data, const std::array<uint8_t, 16>& iv, const std::array<uint8_t, 16>& key);
std::vector<uint8_t> hash(const std::vector<uint8_t>& data);

std::vector<uint8_t> read_file(const std::string& fname);
void write_file(const std::string& fname, const std::vector<uint8_t>& data, bool append = false);

std::array<uint8_t, 16> parse_key(const std::string& input);

void encrypt_file(const std::string& infile, const std::string& outfile, const std::array<uint8_t, 16>& iv, const std::array<uint8_t, 16>& key);
void decrypt_file(const std::string& infile, const std::string& outfile, const std::array<uint8_t, 16>& iv, const std::array<uint8_t, 16>& key);
#endif
