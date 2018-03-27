#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <vector>
#include <array>
#include <stdint.h> 
#include <cstring>
#include <utility>
#include "mbedtls/aes.h"
#include "mbedtls/bignum.h"
#include "mbedtls/cmac.h"
#include "mbedtls/cipher.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509.h"

namespace cry {

class RSAKey {
    mbedtls_rsa_context ctx[1];
public:
    RSAKey() {
        mbedtls_rsa_init(ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    }

    RSAKey(const RSAKey& other) {
        mbedtls_rsa_copy(ctx, other.ctx);
    }

    RSAKey& operator=(const RSAKey& other) {
        mbedtls_rsa_free(ctx);
        mbedtls_rsa_copy(ctx, other.ctx);
        return *this;
    }

    mbedtls_rsa_context* get() {
        return ctx;
    }

    const mbedtls_rsa_context* get() const {
        return ctx;
    }

    bool has_pub() const {
        return mbedtls_rsa_check_pubkey(ctx) == 0;
    }

    bool has_priv() const {
        return mbedtls_rsa_check_privkey(ctx) == 0;
    }

    ~RSAKey() {
        mbedtls_rsa_free(ctx);
    }
};

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
std::vector<uint8_t> encrypt_rsa(const C& data, RSAKey& key) {
    std::vector<uint8_t> result;

    if(!key.has_pub())
        return result;

    result.resize(512);

    const char *pers = "rsa_decrypt";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers,strlen(pers));


    mbedtls_rsa_pkcs1_encrypt(key.get(), mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, data.size(), data.data(), result.data());
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
std::vector<uint8_t> decrypt_rsa(const std::vector<uint8_t>& data, cry::RSAKey& key) {
    std::vector<uint8_t> result;
    if (!key.has_priv())
        return result;

    result.resize(512);
    const char *pers = "rsa_decrypt";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    size_t i = 512;
    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers,strlen(pers));

    mbedtls_rsa_pkcs1_decrypt(key.get(), mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i, data.data(), result.data(), 512);

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

/**
 * Fill a container with random data
 *
 * @param data - container
 */
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

void generate_rsa_keys(RSAKey& rsa_pub, RSAKey& rsa_priv) {
    int exponent = 65537;
    unsigned int key_size = 4096;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E;
    const char *pers = "rsa_genkey";

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,(const unsigned char *) pers, strlen(pers));

    mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, key_size, exponent);
    mbedtls_rsa_export( &rsa, &N, &P, &Q, &D, &E );

    mbedtls_rsa_import(rsa_pub.get(), &N, NULL, NULL, NULL, &E);
    mbedtls_rsa_import(rsa_priv.get(), &N, &P, &Q, &D, &E);

    mbedtls_rsa_complete(rsa_priv.get());
    mbedtls_rsa_complete(rsa_pub.get());

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

template <typename C>
std::array<uint8_t, 32> mac_data(const C& data, std::array<uint8_t, 32> key) {
    const mbedtls_cipher_info_t *cipher_info;
    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
    std::array<uint8_t, 32> output;

    mbedtls_cipher_cmac(cipher_info, key.data(), key.size(), data.data(), data.size(), output.data());
    return output; 
} 



template <typename C>
bool check_mac(const C& data, std::array<uint8_t, 32> key, std::array<uint8_t, 32> mac_to_check) {
    std::array<uint8_t, 32> act_mac = cry::mac_data(data, key);
    return !(act_mac == mac_to_check);
}

} // namespace cry

#endif
