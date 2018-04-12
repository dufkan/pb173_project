#ifndef CRYBOX_HPP
#define CRYBOX_HPP

#include "crypto.hpp"

/**
 * Interface for accessing CryBox
 *
 * CryBox is a stateful object with encrypt and decrypt methods.
 */
class CryBox {
public:
    /**
     * Encrypt input data with respect to current state.
     *
     * @param data - Input
     * @return Encrypted output
     */
    virtual std::vector<uint8_t> encrypt(std::vector<uint8_t> data) = 0;

    /**
     * Decrypt input data with respect to current state.
     *
     * @param data - Encrypted input
     * @return Decrypted output
     */
    virtual std::vector<uint8_t> decrypt(std::vector<uint8_t> data) = 0;
};

/**
 * Identity Crybox
 *
 * Does nothing.
 */
class IdBox : public CryBox {
public:
    std::vector<uint8_t> encrypt(std::vector<uint8_t> data) {
        return data;
    }

    std::vector<uint8_t> decrypt(std::vector<uint8_t> data) {
        return data;
    }
};

/**
 * AES Crybox
 *
 * Encrypts and decrypts using AES-256 with key set in constructor.
 */
class AESBox : public CryBox {
    std::array<uint8_t, 32> key;
public:
    AESBox(std::array<uint8_t, 32> key): key(key) {}

    std::vector<uint8_t> encrypt(std::vector<uint8_t> data) {
        return cry::encrypt_aes(data, {}, key);
    }

    std::vector<uint8_t> decrypt(std::vector<uint8_t> data) {
        return cry::decrypt_aes(data, {}, key);
    }
};


/**
 * MAC Crybox
 *
 *
 */
class MACBox : public CryBox {
    std::array<uint8_t,32> key;
public:
    MACBox(std::array<uint8_t, 32> key): key(cry::hash_sha(key)) {}
    MACBox(std::vector<uint8_t> key)    : key(cry::hash_sha(key)) {}

    std::vector<uint8_t> encrypt(std::vector<uint8_t> data) {
        std::array<uint8_t,32> mac = cry::mac_data(data, key);
        data.insert(data.end(),mac.begin(),mac.end());
        return data;
    }


    std::vector<uint8_t> decrypt(std::vector<uint8_t> data) {
        std::array<uint8_t,32> mac;
        std::copy(data.end()-32,data.end(),mac.begin());
        //std::vector<uint8_t> macc(data.end()-32,data.end());
        data.resize(data.size()-32);
        if (mac != cry::mac_data(data,key)) {
            /*Trouble with integrity*/   //TODO exception
            //std::cerr << "Trouble with integrity in MACBox." << std::endl;
        }
        return data;
    }

    std::array<uint8_t, 32> get_key() {
        return key;
    }
};
#endif
