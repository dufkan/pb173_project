#ifndef CRYBOX_HPP
#define CRYBOX_HPP

#include "crypto.hpp"
#include <numeric>

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

    virtual ~CryBox() {};
};

/**
 * Identity Crybox
 *
 * Does nothing.
 */
class IdBox : public CryBox {
public:
    std::vector<uint8_t> encrypt(std::vector<uint8_t> data) override {
        return data;
    }

    std::vector<uint8_t> decrypt(std::vector<uint8_t> data) override {
        return data;
    }
};

/**
 * AES Crybox
 *
 * Encrypts and decrypts using AES-256 with key set in constructor.
 */
class AESBox : public CryBox {
#ifdef TESTMODE
public:
#endif
    std::array<uint8_t, 32> key;

public:
    AESBox(std::array<uint8_t, 32> key): key(key) {}

    std::vector<uint8_t> encrypt(std::vector<uint8_t> data) override {
        return cry::encrypt_aes(data, {}, key);
    }

    std::vector<uint8_t> decrypt(std::vector<uint8_t> data) override {
        return cry::decrypt_aes(data, {}, key);
    }
};


/**
 * MAC Crybox
 *
 * MACs and unMACs using key wet in constructor.
 */
class MACBox : public CryBox {
#ifdef TESTMODE
public:
#endif
    std::array<uint8_t, 32> key;
public:
    MACBox(std::array<uint8_t, 32> key): key(cry::hash_sha(key)) {}

    std::vector<uint8_t> encrypt(std::vector<uint8_t> data) override {
        std::array<uint8_t, 32> mac = cry::mac_data(data, key);
        data.insert(data.end(), mac.begin(), mac.end());
        return data;
    }

    std::vector<uint8_t> decrypt(std::vector<uint8_t> data) override {
        std::array<uint8_t, 32> mac;
        std::copy(data.end() - 32, data.end(), mac.begin());
        data.resize(data.size() - 32);
        if (mac != cry::mac_data(data, key))
            throw std::runtime_error{"Invalid MAC."};
        return data;
    }
};

/**
 * Sequence Crybox
 *
 * Chains crybox calls.
 */
class SeqBox : public CryBox {
#ifdef TESTMODE
public:
#endif
    std::vector<std::unique_ptr<CryBox>> boxes;
public:
    SeqBox(CryBox* box) {
        boxes.emplace_back(box);
    }

    SeqBox(std::unique_ptr<CryBox> box) {
        boxes.push_back(std::move(box));
    }

    SeqBox(std::initializer_list<CryBox*> bxs) {
        for(auto box : bxs)
            boxes.emplace_back(box);
    }

    std::vector<uint8_t> encrypt(std::vector<uint8_t> data) override {
        for(auto it = boxes.begin(); it != boxes.end(); ++it)
            data = (*it)->encrypt(std::move(data));
        return data;
    }

    std::vector<uint8_t> decrypt(std::vector<uint8_t> data) override {
        for(auto it = boxes.rbegin(); it != boxes.rend(); ++it)
            data = (*it)->decrypt(std::move(data));
        return data;
    }
};

/**
 * DoubleRatchet Crybox
 */
class DRBox : public CryBox {
    std::array<uint8_t, 32> RK;
    std::array<uint8_t, 32> CKs;
    std::array<uint8_t, 32> CKr;
    cry::ECKey DHs;
    cry::ECKey DHr;
    size_t Ns = 0;
    size_t Nr = 0;
    size_t PN = 0;
    // MKSKIPPED

    static std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 32>> kdf_RK(const std::array<uint8_t, 32>& k, const std::array<uint8_t, 32>& input) {
        std::vector<uint8_t> concat;
        concat.insert(concat.end(), k.begin(), k.end());
        concat.insert(concat.end(), input.begin(), input.end());
        auto newkey = cry::hash_sha(concat);
        return {newkey, cry::hash_sha(newkey)};
    }

    static std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 32>> kdf_CK(const std::array<uint8_t, 32>& k) {
        auto newkey = cry::hash_sha(k);
        return {newkey, cry::hash_sha(newkey)};
    }

public:
    /**
     * Constructs DRBox of the client initiating the communication
     */
    DRBox(std::array<uint8_t, 32> SK, std::array<uint8_t, 32> key) {
        DHs.gen_pub_key();
        //DHr = bob_dh_public_key
        //std::tie(RK, CKs) = kdf_RK(SK, DH(DHs, DHr));
    }

    /**
     * Constructs DRBox of the client being contacted
     */
    DRBox(std::array<uint8_t, 32> SK, cry::ECKey DHs): RK(SK), DHs(DHs) {
        std::iota(CKs.begin(), CKs.end(), 0); // tmp
        std::iota(CKr.begin(), CKr.end(), 0); // tmp
    }

    std::vector<uint8_t> encrypt(std::vector<uint8_t> data) override {
        auto [newkey, enckey] = kdf_CK(CKs); // symmetric ratchet
        CKs = std::move(newkey);
        return cry::encrypt_aes(data, {}, enckey);
    }

    std::vector<uint8_t> decrypt(std::vector<uint8_t> data) override {
        auto [newkey, deckey] = kdf_CK(CKr); // symmetric ratchet
        CKr = std::move(newkey);
        return cry::decrypt_aes(data, {}, deckey);
    }
};
#endif
