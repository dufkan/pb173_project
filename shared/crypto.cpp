#include "crypto.hpp"



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


std::vector<uint8_t> cry::encrypt_aes(const std::vector<uint8_t>& data, std::array<uint8_t, 16> iv, const std::array<uint8_t, 32>& key) {
    std::vector<uint8_t> result;
    result.resize(data.size());

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key.data(), 256);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, data.size(), iv.data(), data.data(), result.data());
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

    return result;
}


std::vector<uint8_t> cry::encrypt_rsa(const std::vector<uint8_t>& data, mbedtls_rsa_context* rsa_pub) {
    std::vector<uint8_t> result;
    

    if((mbedtls_rsa_complete(rsa_pub)!=0) || mbedtls_rsa_check_pubkey(rsa_pub)){
	    result.resize(1);
	    return result;
    }
    result.resize(256);

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


std::vector<uint8_t> cry::decrypt_rsa(const std::vector<uint8_t>& data,  mbedtls_rsa_context* rsa_priv) {
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
    size_t i = 256;
    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers,strlen(pers));

    mbedtls_rsa_pkcs1_decrypt(rsa_priv, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i, data.data(), result.data(),1024);

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return result;
}


std::array<uint8_t, 32> cry::hash_sha(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 32> result;
    mbedtls_sha256_ret(data.data(), data.size(), result.data(), 0);
    return result;
}


bool cry::check_hash(std::vector<uint8_t> data, std::array<uint8_t, 32> control_hash) {
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


void cry::generate_rsa_keys(mbedtls_rsa_context* rsa_pub, mbedtls_rsa_context* rsa_priv){
    int exponent = 65537;
    unsigned int key_size = 2048;
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
    
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E );
    mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
}	


/*
std::array<uint8_t,32> create_symmetric_key(std::vector<uint8_t> first_part, std::vector<uint8_t> second_part) {
    first_part.insert(first_part.end(),second_part.begin(),second_part.end());
    return cry::hash_sha(first_part);
}*/
