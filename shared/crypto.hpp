#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <vector>
#include <array>
#include <stdint.h> 
#include <cstring>
#include "mbedtls/aes.h"
#include "mbedtls/bignum.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509.h"

namespace cry {

/**
 * Pad given data vector using PKCS#7 padding method
 *
 * @param data Input data vector
 * @param bsize Block width to pad to
 */
void pad(std::vector<uint8_t>& data, uint8_t bsize) {
    int8_t val = bsize - (data.size() % bsize);
    for(uint8_t i = 0; i < val; ++i)
    data.push_back(val);
}

/**
 * Unpad given data vector using PKCS#7 padding method
 *
 * @param data Input data vector
 * @param bsize Block width to unpad to
 */
void unpad(std::vector<uint8_t>& data, uint8_t bsize) {
    if(data.size() < bsize) return;
    uint8_t val = data[data.size() - 1];
    if(val > bsize) return;
    data.resize(data.size() - val);
}

/**
 * Encrypt data vector with given key and IV by AES-256 in CBC mode
 *
 * @param data Input data vector
 * @param iv Initial vector for CBC
 * @param key AES-256 key
 *
 * @return Vector of encrypted data
 */
template <typename C>
std::vector<uint8_t> encrypt_aes(const C& data, std::array<uint8_t, 16> iv, const std::array<uint8_t, 32>& key) {
    std::vector<uint8_t> mut_data{std::begin(data), std::end(data)};
    pad(mut_data, 32);
    std::vector<uint8_t> result;
    result.resize(mut_data.size());

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key.data(), 256);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, mut_data.size(), iv.data(), mut_data.data(), result.data());
    mbedtls_aes_free(&ctx);

    return result;
}

/**
 * Decrypt data vector with given key and IV by AES-256 in CBC mode
 *
 * @param data Input data vector
 * @param iv Initial vector for CBC
 * @param key AES-256 key
 *
 * @return Vector of decrypted data
 */
std::vector<uint8_t> decrypt_aes(const std::vector<uint8_t>& data, std::array<uint8_t, 16> iv, const std::array<uint8_t, 32>& key) {
    std::vector<uint8_t> result;
    result.resize(data.size());

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, key.data(), 256);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, data.size(), iv.data(), data.data(), result.data());
    mbedtls_aes_free(&ctx);

    unpad(result, 32);
    return result;
}

/**
 * Encrypt data vector with given public RSA-2048 key
 *
 * @param data Input data vector
 * @param rsa_pub rsa context with public key to use for encryption
 *
 * @return Vector of encrypted data
 */
template <typename C>
std::vector<uint8_t> encrypt_rsa(const C& data, mbedtls_rsa_context* rsa_pub) {
    std::vector<uint8_t> result;

    if((mbedtls_rsa_complete(rsa_pub)!=0) || mbedtls_rsa_check_pubkey(rsa_pub)){
        result.resize(1);
        return result;
    }
    result.resize(512);

    const char *pers = "rsa_decrypt";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers,strlen(pers));


    mbedtls_rsa_pkcs1_encrypt(rsa_pub, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, data.size(), data.data(), result.data());
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return result;

}

/**
 * Decrypt data vector with given private RSA-2048 key
 *
 * @param data Input data vector
 * @param pubkey Private key to use for decryption
 *
 * @return Vector of encrypted data
 */
std::vector<uint8_t> decrypt_rsa(const std::vector<uint8_t>& data, mbedtls_rsa_context* rsa_priv) {
    std::vector<uint8_t> result;
    result.resize(data.size());
    if (mbedtls_rsa_complete(rsa_priv)!=0) {
            result.resize(1);
            return result;
    }
    result.resize(512);
    const char *pers = "rsa_decrypt";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    size_t i = 512;
    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers,strlen(pers));

    mbedtls_rsa_pkcs1_decrypt(rsa_priv, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i, data.data(), result.data(),1024);

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return result;
}

/**
 * Hash data by SHA2-256
 *
 * @param data Input data
 *
 * @return Hashed input data
 */
std::array<uint8_t, 32> hash_sha(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 32> result;
    mbedtls_sha256_ret(data.data(), data.size(), result.data(), 0);
    return result;
}

/**
 * Generate data hash and compare it with control_hash
 * 
 * @param data - input data
 * @param control_hash
 */
bool check_hash(const std::vector<uint8_t>& data, const std::array <uint8_t,32>& control_hash) {
    std::array<uint8_t, 32> act_hash;
    mbedtls_sha256_ret(data.data(), data.size(), act_hash.data(), 0);
    return (act_hash==control_hash);
}

/** 
 * Generate random data of the length len
 *
 * @param len - length of the data
 * @return - block of random data of length len
 */
std::vector<uint8_t> get_random_data(size_t len) {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    std::vector<uint8_t> result;
    result.resize(len);

    const char *pers = "some random string";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers, strlen(pers));
    mbedtls_ctr_drbg_random( &ctr_drbg, result.data(), len);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return result;
}

template<typename C>
void random_data(C& data) {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    const char *pers = "some random string";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers, strlen(pers));
    mbedtls_ctr_drbg_random( &ctr_drbg, data.data(), data.size());
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
}


/**
 * Create new pair od keys for RSA
 *
* @param prikey - the new private key will be saved here
 * @param pubkey - the new public key will be saved here
 */

void generate_rsa_keys(mbedtls_rsa_context* rsa_pub, mbedtls_rsa_context* rsa_priv) {
    int exponent = 65537;
    unsigned int key_size = 4096;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E;
    const char *pers = "rsa_genkey";

    mbedtls_rsa_free(rsa_pub);mbedtls_rsa_free(rsa_priv);
    mbedtls_rsa_init(rsa_pub, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    mbedtls_rsa_init(rsa_priv, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,(const unsigned char *) pers, strlen(pers));

    mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, key_size, exponent);
    mbedtls_rsa_export( &rsa, &N, &P, &Q, &D, &E );

    mbedtls_rsa_import(rsa_pub, &N, NULL, NULL, NULL, &E);
    mbedtls_rsa_import(rsa_priv, &N, &P, &Q, &D, &E);
    
    mbedtls_rsa_complete(rsa_priv); mbedtls_rsa_complete(rsa_pub);

    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E );
    mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
}	


/**
 * Create key by hashing data from fisrt_part and second_part
 *
 * @param first_part - data from challenge
 * @param second_part - data from response
 * @return symetric key created from chall and resp
 */

std::array<uint8_t,32> create_symmetric_key(std::vector<uint8_t> first, std::vector<uint8_t> second) {
    first.resize(first.size() + second.size());
    first.insert(first.end(),second.begin(),second.end());
    return cry::hash_sha(first);
}

} 

// namespace cry


#endif
