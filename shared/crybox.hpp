#ifndef CRYBOX_HPP
#define CRYBOX_HPP

#include "crypto.hpp"
#include <numeric>
#include <vector>
#include <map>
#include <array>

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
    WithoutKey,
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
    cry::ECKey DHs;     /*Ratchet key pair - sending* & receiving*/

    uint16_t Ns = 0;      /*Message numbers for sending*/
    uint16_t Nr = 0;      /*Message numbers for receiving*/
    uint16_t PN = 0;      /*Number of message in previous sending chain*/
    bool pubkey_to_send = false;
    std::map<uint16_t, std::array<uint8_t, 32>> SKIPPED;  /*Skipped-over message keys*/


    /**
     * Key Derivation Function for Ratchet key
     *
     * @param k - The (root key) key used to derive new keys
     * @param input - Input (public key from other side) used to derive new keys
     * @return Two keys, new RK and CK
     */
    static std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 32>> kdf_RK(const std::array<uint8_t, 32>& k, const std::array<uint8_t, 32>& input) {
        std::vector<uint8_t> concat;
        concat.insert(concat.end(), k.begin(), k.end());
        concat.insert(concat.end(), input.begin(), input.end());
        auto newkey = cry::hash_sha(concat);
        return {newkey, cry::hash_sha(newkey)};
    }


    /**
     * Key Derivation Function for Chain key
     *
     * @param k - CK used in deriving
     * @return Two keys, new CK and key for encrypting/decrypting
     */
    static std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 32>> kdf_CK(const std::array<uint8_t, 32>& k) {
        auto newkey = cry::hash_sha(k);
        return {newkey, cry::hash_sha(newkey)};
    }


    /**
     * Ratchet with generating new EC key pair and computing new shared secret key, RK
     *
     * @param pub_key - Public key of other side, used for ECDH
     */ 
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

    /**
     * Create a header for message.
     *
     * @param key - Key, whose public part should be sent
     * @param PN - Number of messages in previous chain
     * @param N - Number of messages in current sending chain
     * @return The message header.
     */
    static std::vector<uint8_t> create_header(std::optional<std::array<uint8_t, 32>> key, uint16_t PN, uint16_t N) {
        Encoder e;
        if (key) {
            e.put(static_cast<uint8_t>(DHKey::WithKey));
            e.put(*key);
        }
        else {
            e.put(static_cast<uint8_t>(DHKey::WithoutKey));
        }
        e.put(static_cast<uint16_t>(PN));
        e.put(static_cast<uint16_t>(N));
        return e.move();
    }

    /**
     * Parse a message header
     *
     * @param msg - The message
     * @return Tripple of sending-side public key, number of messages in previous chain, and number of messages in current chain.
     */
    std::tuple<std::optional<std::array<uint8_t, 32>>, uint16_t, uint16_t> parse_header(std::vector<uint8_t>& msg) const {
        RefDecoder d{msg};
        auto tag = static_cast<DHKey>(d.get_u8());
        std::optional<std::array<uint8_t, 32>> key;
        if(tag == DHKey::WithKey)
            key = d.get_arr<32>();
        auto PN = d.get_u16();
        auto N = d.get_u16();
        d.cut();
        return {key, PN, N};
    }

public:
    /**
     * Constructs DRBox of the client initiating the communication
     *
     * @param SK - Shared secret key
     * @param pub_key - Public key of other side
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
     *
     * @param SK - Shared secret key
     * @param DHs - ECKey, other side has its public key
     */
    DRBox(std::array<uint8_t, 32> SK, cry::ECKey DHs): RK(SK), DHs(DHs) { 
        CKr = {}; CKs = {}; 
    }


    /**
     * Encrypting message
     * if a public key should be send, then insert it to the message
     *
     * @param data - data to encrypt
     * @return vector of encrypted data (and new public key)
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t> data) override {
        auto [newkey, enckey] = kdf_CK(CKs);
        CKs = std::move(newkey);

        std::optional<std::array<uint8_t, 32>> key;
        if(pubkey_to_send) {
            key = DHs.get_bin_q();
            PN = Ns;
            Ns = 0;
        }
        else {
            ++Ns;
        }
        Encoder e;
        e.put(create_header(key, PN, Ns));
        e.put(cry::encrypt_aes(data, {}, enckey));
        return e.move();
    }


    /**
     * Decrypting message
     * if a new public key is received, then DHratchet is called
     *
     * @param data - data to be decrypted
     * @return decrypted data (without new public key)
     */
    std::vector<uint8_t> decrypt(std::vector<uint8_t> data) override {
        auto [key, PN, N] = parse_header(data);
        if(N > Nr + 1) { // Skipped
            if(key) {
                SKIPPED = {};
                while(Nr++ != PN) {
                    std::tie(CKr, SKIPPED[Nr]) = kdf_CK(CKr);
                }
                Nr = 0;
            }
            else {
                while(Nr++ != N + 1) {
                    std::tie(CKr, SKIPPED[Nr]) = kdf_CK(CKr);
                }
            }
        }
        else if(N < Nr + 1) { // Received skipped
            return cry::decrypt_aes(data, {}, SKIPPED[N]);
        }
        if(key)
            DHRatchet(*key);

        auto [newkey, deckey] = kdf_CK(CKr);
        CKr = std::move(newkey);
        ++Nr;

        return cry::decrypt_aes(data, {}, deckey);
    }
};
#endif
