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
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509.h"

#include "codec.hpp"


namespace cry {

using AESKey = std::array<uint8_t, 32>;

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

    bool is_correct_priv(const RSAKey& other) const {
        return has_priv() && mbedtls_rsa_check_pub_priv(other.ctx, ctx) == 0;
    }
    
    /**
     * Export public key to vector of bytes
     *
     * @return vector<uint8_t> with pubkey param
     */
    std::vector<uint8_t> export_pub() const;



    /**
     * Export everyting from RSA key
     * 
     * @return vector<uint8_t> with all parameters from RSA key
     */
    std::vector<uint8_t> export_all() const;
 

    /**
     * Import from vector of bytes to RSA param
     * 
     */
    void import(const std::vector<uint8_t>& key);


    ~RSAKey() {
        mbedtls_rsa_free(ctx);
    }
}; //class RSAKey


class ECKey {
    mbedtls_ecdh_context ctx;

public : 
    ECKey() {
        mbedtls_ecdh_init(&ctx);
        mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_CURVE25519);
    }

    ECKey(const ECKey& other) {
        mbedtls_ecdh_init(&ctx);
        mbedtls_ecp_copy(&ctx.Q, &other.ctx.Q);
        mbedtls_ecp_group_copy(&ctx.grp, &other.ctx.grp);
    }


    ECKey& operator=(const ECKey& other) {
        mbedtls_ecdh_free(&ctx);
        mbedtls_ecp_copy(&ctx.Q, &other.ctx.Q);
        mbedtls_ecp_group_copy(&ctx.grp, &other.ctx.grp);
        return *this;
    }


    mbedtls_ecdh_context* get() {
        return &ctx;
    }

    const mbedtls_ecdh_context* get() const {
        return &ctx;
    }


    /**
     * Generate ECDH keypair
     * 
     */
    void gen_pub_key();


    /**
     * Get point Q binary
     *
     */
    std::array<uint8_t,32> get_bin_q();

    /**
     * Load from binary data point Qp
     *
     */ 
    void load_bin_qp(const std::array<uint8_t,32>& point);

    /**
     * Compute shared secret
     *
     */ 
    void compute_shared(); 


    bool compare_shared(const mbedtls_ecdh_context& other) {
        return !(mbedtls_mpi_cmp_mpi(&ctx.z, &other.z));
    }


    /**
     * Return the shared secret in binary array
     *
     */
    std::array<uint8_t,32> get_shared();

    bool has_priv() const {
        return mbedtls_ecp_check_privkey(&ctx.grp,&ctx.d) == 0;
    }
    
    bool has_pub() const {
        return mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Q) == 0; 
    }

    bool is_correct_priv(const ECKey& other) const;


}; //ECKey


/**
 * Pad given data vector using PKCS#7 padding method
 *
 * @param data Input data vector
 * @param bsize Block width to pad to
 */
void pad(std::vector<uint8_t>& data, uint8_t bsize); 



/**
 * Unpad given data vector using PKCS#7 padding method
 *
 * @param data Input data vector
 * @param bsize Block width to unpad to
 */
void unpad(std::vector<uint8_t>& data, uint8_t bsize); 



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
std::vector<uint8_t> encrypt_aes(const C& data, std::array<uint8_t, 16> iv, const std::array<uint8_t, 32>& key); 



/**
 * Decrypt data vector with given key and IV by AES-256 in CBC mode
 *
 * @param data Input data vector
 * @param iv Initial vector for CBC
 * @param key AES-256 key
 *
 * @return Vector of decrypted data
 */
std::vector<uint8_t> decrypt_aes(const std::vector<uint8_t>& data, std::array<uint8_t, 16> iv, const std::array<uint8_t, 32>& key);

 

/**
 * Encrypt data vector with given public RSA-2048 key
 *
 * @param data Input data vector
 * @param rsa_pub rsa context with public key to use for encryption
 *
 * @return Vector of encrypted data
 */
template <typename C>
std::vector<uint8_t> encrypt_rsa(const C& data, RSAKey& key);

 

/**
 * Decrypt data vector with given private RSA-2048 key
 *
 * @param data Input data vector
 * @param pubkey Private key to use for decryption
 *
 * @return Vector of encrypted data
 */
std::vector<uint8_t> decrypt_rsa(const std::vector<uint8_t>& data, cry::RSAKey& key); 



/**
 * Hash data by SHA2-256
 *
 * @param data Input data
 *
 * @return Hashed input data
 */
template<typename C>
std::array<uint8_t, 32> hash_sha(const C& data); 



/**
 * Generate data hash and compare it with control_hash
 * 
 * @param data - input data
 * @param control_hash
 */
bool check_hash(const std::vector<uint8_t>& data, const std::array <uint8_t,32>& control_hash);



/**
 * Generate random data of the length len
 *
 * @param len - length of the data
 * @return - block of random data of length len
 */
std::vector<uint8_t> get_random_data(size_t len); 



/**
 * Fill a container with random data
 *
 * @param data - container
 */
template<typename C>
void random_data(C& data); 



/**
 * Create new pair od keys for RSA
 *
* @param prikey - the new private key will be saved here
 * @param pubkey - the new public key will be saved here
 */

void generate_rsa_keys(RSAKey& rsa_pub, RSAKey& rsa_priv);


 
/**
 * Create key by hashing data from fisrt_part and second_part
 *
 * @param first_part - data from challenge
 * @param second_part - data from response
 * @return symetric key created from chall and resp
 */
std::array<uint8_t,32> create_symmetric_key(std::vector<uint8_t> first, std::vector<uint8_t> second); 



/**
 * Generate MAC
 *
 * @param data
 * @param key
 * @return MAC for data and key
 */
template <typename C>
std::array<uint8_t, 32> mac_data(const C& data, std::array<uint8_t, 32> key);



/**
 * Check if MAC is ok for data and key
 *
 * @param data
 * @param key
 * @return true if MAC is ok
 */
template <typename C>
bool check_mac(const C& data, std::array<uint8_t, 32> key, std::array<uint8_t, 32> mac_to_check); 

} // namespace cry




std::vector<uint8_t> cry::RSAKey::export_pub() const {
    Encoder e;
    std::vector<uint8_t> N, P, Q, D, E;
    N.resize(1024);
    P.resize(1024);
    Q.resize(1024);
    D.resize(1024);
    E.resize(1024);
    mbedtls_rsa_export_raw(ctx, N.data(), 1024, nullptr, 1024, nullptr, 1024, nullptr, 1024, E.data(), 1024);
    e.put(N);
    e.put(P);
    e.put(Q);
    e.put(D);
    e.put(E);
    return e.move();
}



std::vector<uint8_t> cry::RSAKey::export_all() const {
    Encoder e;
    std::vector<uint8_t> N, P, Q, D, E;
    N.resize(1024);
    P.resize(1024);
    Q.resize(1024);
    D.resize(1024);
    E.resize(1024);
    mbedtls_rsa_export_raw(ctx, N.data(), 1024, P.data(), 1024, Q.data(), 1024, D.data(), 1024, E.data(), 1024);
    e.put(N);
    e.put(P);
    e.put(Q);
    e.put(D);
    e.put(E);
    return e.move();
}
 

void cry::RSAKey::import(const std::vector<uint8_t>& key) {
    mbedtls_rsa_import_raw(ctx, key.data(), 1024, key.data() + 1024, 1024, key.data() + 2*1024, 1024, key.data() + 3*1024, 1024, key.data() + 4*1024, 1024);
    mbedtls_rsa_complete(ctx);
}


void cry::ECKey::gen_pub_key() {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ec_gen_pu_lkey";
   
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));
    mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q, mbedtls_ctr_drbg_random, &ctr_drbg);      
       
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
}


std::array<uint8_t,32> cry::ECKey::get_bin_q() {
    std::array<uint8_t,32> buf = {};
    mbedtls_mpi_write_binary(&ctx.Q.X, buf.data(), 32);
    return buf;
}


void cry::ECKey::load_bin_qp(const std::array<uint8_t,32>& point) {
    mbedtls_mpi_lset(&ctx.Qp.Z,1);
    mbedtls_mpi_read_binary(&ctx.Qp.X, point.data(), 32);       
}


void cry::ECKey::compute_shared() {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdh_compute_share"; 
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));

    mbedtls_ecdh_compute_shared(&ctx.grp, &ctx.z, &ctx.Qp, &ctx.d, mbedtls_ctr_drbg_random, &ctr_drbg);
        
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}


std::array<uint8_t,32> cry::ECKey::get_shared() {
    std::array<uint8_t,32> shared;
    std::cout << mbedtls_mpi_write_binary(&ctx.z,shared.data(),shared.size()) << std::endl;
    return std::move(shared);
}


bool cry::ECKey::is_correct_priv(const ECKey& other) const {
    mbedtls_ecp_keypair priv;
    mbedtls_ecp_keypair pub;
    mbedtls_ecp_keypair_init(&priv);
    mbedtls_ecp_keypair_init(&pub);

    mbedtls_mpi_copy(&priv.d, &ctx.d);
    //mbedtls_mpi_copy(&pub.d, &(other.get())->d);
    mbedtls_ecp_group_copy(&priv.grp,&ctx.grp);
    mbedtls_ecp_group_copy(&pub.grp,&(other.get())->grp);
    mbedtls_ecp_copy(&priv.Q,&ctx.Q);
    mbedtls_ecp_copy(&pub.Q, &(other.get())->Q);  

    bool ret = (mbedtls_ecp_check_pub_priv(&pub, &priv)==0);
    mbedtls_ecp_keypair_free(&priv);
    mbedtls_ecp_keypair_free(&pub);
    return has_priv() && ret;
}


void cry::pad(std::vector<uint8_t>& data, uint8_t bsize) {
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

template <typename C>
std::vector<uint8_t> cry::encrypt_aes(const C& data, std::array<uint8_t, 16> iv, const std::array<uint8_t, 32>& key) {
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

std::vector<uint8_t> cry::decrypt_aes(const std::vector<uint8_t>& data, std::array<uint8_t, 16> iv, const std::array<uint8_t, 32>& key) {
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

template <typename C>
std::vector<uint8_t> cry::encrypt_rsa(const C& data, RSAKey& key) {
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

std::vector<uint8_t> cry::decrypt_rsa(const std::vector<uint8_t>& data, cry::RSAKey& key) {
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

template<typename C>
std::array<uint8_t, 32> cry::hash_sha(const C& data) {
    std::array<uint8_t, 32> result;
    mbedtls_sha256_ret(data.data(), data.size(), result.data(), 0);
    return result;
}

bool cry::check_hash(const std::vector<uint8_t>& data, const std::array <uint8_t,32>& control_hash) {
    std::array<uint8_t, 32> act_hash;
    mbedtls_sha256_ret(data.data(), data.size(), act_hash.data(), 0);
    return (act_hash==control_hash);
}

std::vector<uint8_t> cry::get_random_data(size_t len) {
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
void cry::random_data(C& data) {
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


void cry::generate_rsa_keys(RSAKey& rsa_pub, RSAKey& rsa_priv) {
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


std::array<uint8_t,32> cry::create_symmetric_key(std::vector<uint8_t> first, std::vector<uint8_t> second) {
    first.resize(first.size() + second.size());
    first.insert(first.end(),second.begin(),second.end());
    return cry::hash_sha(first);
}

template <typename C>
std::array<uint8_t, 32> cry::mac_data(const C& data, std::array<uint8_t, 32> key) {
    const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
    std::array<uint8_t, 32> output{};

    mbedtls_cipher_context_t ctx[1];
    mbedtls_cipher_init(ctx);
    mbedtls_cipher_setup(ctx, cipher_info);
    mbedtls_cipher_cmac_starts(ctx, key.data(), 256);
    if(data.size() != 0)
        mbedtls_cipher_cmac_update(ctx, data.data(), data.size());
    mbedtls_cipher_cmac_finish(ctx, output.data());
    return output;
}



template <typename C>
bool cry::check_mac(const C& data, std::array<uint8_t, 32> key, std::array<uint8_t, 32> mac_to_check) {
    std::array<uint8_t, 32> act_mac = cry::mac_data(data, key);
    return act_mac == mac_to_check;
}

#endif
