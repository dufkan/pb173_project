#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <vector>
#include <array>
#include <stdint.h> 

namespace cry {

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
std::vector<uint8_t> encrypt_aes(const std::vector<uint8_t>& data, std::array<uint8_t, 32> iv, const std::array<uint8_t, 32>& key);

/**
 * Decrypt data vector with given key and IV by AES-256 in CBC mode
 *
 * @param data Input data vector
 * @param iv Initial vector for CBC
 * @param key AES-256 key
 *
 * @return Vector of decrypted data
 */
std::vector<uint8_t> decrypt_aes(const std::vector<uint8_t>& data, std::array<uint8_t, 32> iv, const std::array<uint8_t, 32>& key);

/**
 * Encrypt data vector with given public RSA-2048 key
 *
 * @param data Input data vector
 * @param rsa_pub rsa context with public key to use for encryption
 *
 * @return Vector of encrypted data
 */
std::vector<uint8_t> encrypt_rsa(const std::vector<uint8_t>& data, const mbedtls_rsa_context& rsa_pub)

/**
 * Decrypt data vector with given private RSA-2048 key
 *
 * @param data Input data vector
 * @param pubkey Private key to use for decryption
 *
 * @return Vector of encrypted data
 */
std::vector<uint8_t> decrypt_rsa(const std::vector<uint8_t>& data, const std::vector<uint8_t>& privkey);

/**
 * Hash data by SHA2-256
 *
 * @param data Input data
 *
 * @return Hashed input data
 */
std::array<uint8_t, 32> hash_sha(const std::vector<uint8_t>& data);

/**
 * Generate data hash and compare it with control_hash
 * 
 * @param data - input data
 * @param control_hash
 */
bool check_hash(std::vector<uint8_t> data, std::vector <uint8_t> control_hash);

/** 
 * Generate random data of the length len
 *
 * @param len - length of the data
 */
std::vector<uint8_t> get_random_data(size_t len);

/**
 * Create new pair od keys for RSA
 *
* @param prikey - the new private key will be saved here
 * @param pubkey - the new public key will be saved here
 */
void generate_keys(std::vector<uint8_t> prikey, std::vector<uint8_t> pubkey);


/**
 * Create key by hashing data from fisrt_part and second_part
 *
 * @param first_part - data from challenge
 * @param second_part - data from response
 * @return symetric key created from chall and resp
 */ 
std::vector<uint8_t> create_symmetric_key(std::vector<uint8_t> first_part, std::vector<uint8_t> second_part);






} // namespace cry


#endif
