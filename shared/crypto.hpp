#ifndef CRYPTO_HPP
#define CRYPTO_HPP

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
 * Encrypt data vector with given public RSA key
 *
 * @param data Input data vector
 * @param pubkey Public key to use for encryption
 *
 * @return Vector of encrypted data
 */
std::vector<uint8_t> encrypt_rsa(const std::vector<uint8_t>& data, const std::vector<uint8_t>& pubkey);

/**
 * Decrypt data vector with given private RSA key
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

} // namespace cry


#endif
