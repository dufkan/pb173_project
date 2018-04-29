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


enum class DHKey {
    WithKey,
    WithoutKey
};


/**
 * DoubleRatchet Crybox
 */
class DRBox : public CryBox {
#ifdef TESTMODE
public:
#endif
    std::array<uint8_t, 32> RK;     /*Root Key*/
    std::array<uint8_t, 32> CKs;    /*Chain Key for sending*/
    std::array<uint8_t, 32> CKr;    /*Chain Key for receiving*/
    cry::ECKey DHs;     /*Ratchet key pair - sending* & receiving/

    size_t Ns = 0;      /*Message numbers for sending*/
    size_t Nr = 0;      /*Message numbers for receiving*/
    size_t PN = 0;      /*Number of message in previous sending chain*/
    bool pubkey_to_send = false;
    // MKSKIPPED        /*Skipped-over message keys*/

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

    void DHRatchet(std::array<uint8_t, 32> pub_key) {
        PN = Ns; //promyslet jeste cislovani, nedat tam radsi +Ns ??
        Ns = 0;
        Nr = 0;
        DHs.load_bin_qp(pub_key);
        DHs.compute_shared();
        std::tie(RK, CKr) = kdf_RK(RK, DHs.get_shared());
        DHs.gen_pub_key();
        DHs.compute_shared();
        pubkey_to_send = true;
        std::tie(RK, CKs) = kdf_RK(RK, DHs.get_shared());
    }

public:
    /**
     * Constructs DRBox of the client initiating the communication
     */
    DRBox(std::array<uint8_t, 32> SK, std::array<uint8_t, 32> pub_key) {
        DHs.gen_pub_key();
        DHs.load_bin_qp(pub_key);
        DHs.compute_shared();
        std::tie(RK,CKs) = kdf_RK(SK,DHs.get_shared());
        CKr = {};
        
        pubkey_to_send = true;
    }

    /**
     * Constructs DRBox of the client being contacted
     */
    DRBox(std::array<uint8_t, 32> SK, cry::ECKey DHs): RK(SK), DHs(DHs) { 
        CKr = {}; CKs = {}; 
    }

    std::vector<uint8_t> encrypt(std::vector<uint8_t> data) override {
        Encoder enc;
        if (pubkey_to_send) {
            enc.put(static_cast<uint8_t>(DHKey::WithKey));
            enc.put(DHs.get_bin_q());
            pubkey_to_send = false;
        } else {
            enc.put(static_cast<uint8_t>(DHKey::WithoutKey));
        }
        auto [newkey, enckey] = kdf_CK(CKs); // symmetric ratchet
        CKs = std::move(newkey);
        //enc.put(Ns) - add number
        enc.put(cry::encrypt_aes(data, {}, enckey));
        return enc.move();
    }

    std::vector<uint8_t> decrypt(std::vector<uint8_t> data) override {
        Decoder dec{data};
        DHKey is_there = static_cast<DHKey>(dec.get_u8());
        
        if (is_there == DHKey::WithKey) {
            DHRatchet(dec.get_arr<32>());
        } else if (is_there != DHKey::WithoutKey) {
            std::cerr << "DRBox not WithKey, not WithoutKey " << std::endl;
            //TODO exception asi
        }
//Nr = dec.get_()
        auto [newkey, deckey] = kdf_CK(CKr); // symmetric ratchet
        CKr = std::move(newkey);
        return cry::decrypt_aes(dec.get_vec(), {}, deckey);
    }
};
#endif
