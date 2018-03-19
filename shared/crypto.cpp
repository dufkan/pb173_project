#include "crypto.hpp"
//#include "../libs/mbedtls/include/mbedtls/aes.h"
//#include "../libs/mbedtls/include/mbedtls/sha512.h"
//#include "../libs/mbedtls/include/mbedtls/config.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
#include "mbedtls/config.h"
#include "rsa.h"
#include <vector>

void cry::pad(std::vector<uint8_t>& data, uint8_t bsize){
    int8_t val = bsize - (data.size() % bsize);
    for(uint8_t i = 0; i < val; ++i)
    data.push_back(val);
}


void cry::unpad(std::vector<uint8_t>& data, uint8_t bsize) {
    if(data.size() < bsize) return;
    uint8_t val = data[data.size() - 1];
    if(val > bsize) return;
    data.resize(data.size() - val);
}


std::vector<uint8_t> cry::encrypt_aes(const std::vector<uint8_t>& data, std::array<uint8_t, 32> iv, const std::array<uint8_t, 32>& key) {
    std::vector<uint8_t> result;
    result.resize(data.size());

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key.data(), 256);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, data.size(), iv.data(), data.data(), result.data());
    mbedtls_aes_free(&ctx);

    return result;
}


std::vector<uint8_t> cry::decrypt_aes(const std::vector<uint8_t>& data, std::array<uint8_t, 32> iv, const std::array<uint8_t, 32>& key) {
    std::vector<uint8_t> result;
    result.resize(data.size());

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, key.data(), 256);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, data.size(), iv.data(), data.data(), result.data());
    mbedtls_aes_free(&ctx);

    return result;
}


std::vector<uint8_t> cry::encrypt_rsa(const std::vector<uint8_t>& data, const mbedtls_rsa_context& rsa_pub) {
    std::vector<uint8_t> result;
    result.resize(data.size());
    mbedtls_rsa_public( rsa_pub, data.data(), result.data());
    return result;
}


std::vector<uint8_t> cry::decrypt_rsa(const std::vector<uint8_t>& data, const mbedtls_rsa_context& rsa_priv) {
    std::vector<uint8_t> result;
    result.resize(data.size());
    
    const char *pers = "rsa_decrypt";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    
    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers,strlen(pers));

    mbedtls_rsa_private( rsa_priv, mbedtls_ctr_drbg_random, &ctr_drbg, data.data(), result.data());
    
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
}


std::array<uint8_t, 32> cry::hash_sha(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 32> result;
    mbedtls_sha256_ret(data.data(), data.size(), result.data(), 0);
    return result;
}


bool cry::check_hash(std::vector<uint8_t> data, std::array<uint8_t, 32> control_hash) {
    std::array<uint8_t, 32> act_hash;
    mbedtls_sha256_ret(data.data(), data.size(), act_hash.data(), 0);
    return atc_hash==control_hash;
}



std::vector<uint8_t> get_random_data(size_t len) {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    std::vector<uint8_t> result;
    result.resize(len);

    const char *pers = "some random string";
    int ret;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers, strlen(pers));
    mbedtls_ctr_drbg_random( &ctr_drbg, result.data(), len);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return result;
}


