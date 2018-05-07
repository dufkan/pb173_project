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
    std::array<uint8_t, 32> pubkey;
    std::map<std::pair<std::array<uint8_t, 32>, uint16_t>, std::array<uint8_t, 32>> SKIPPED;

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
     * MAC key derivation function
     *
     * @param k - input data for kdf
     * @return MAC key
     */
    static std::array<uint8_t, 32> kdf_MAC(std::array<uint8_t, 32> k) {
        for(size_t i = 0; i < k.size(); ++i)
            k[i] += i;
        return cry::hash_sha(k);
    }


    /**
     * Ratchet with generating new EC key pair and computing new shared secret key, RK
     *
     * @param pub_key - Public key of other side, used for ECDH
     */ 
    void DHRatchet(std::array<uint8_t, 32> pub_key) {
        PN = Ns; 
        Ns = 0;
        Nr = 0;
        pubkey = pub_key;
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
    static std::vector<uint8_t> create_header(std::array<uint8_t, 32> key, uint16_t PN, uint16_t N) {
        Encoder e;
        e.put(key);
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
    std::tuple<std::array<uint8_t, 32>, uint16_t, uint16_t> parse_header(std::vector<uint8_t>& msg) const {
        RefDecoder d{msg};
        std::array<uint8_t, 32> key;
        key = d.get_arr<32>();
        auto PN = d.get_u16();
        auto N = d.get_u16();
        d.cut();
        return {key, PN, N};
}

    /**
     * Overwite and delete the key saved in SKIPPED
     *
     * @param ipair the pair under it is saved in SKIPPED
     */
    void delete_skey(std::pair<std::array<uint8_t,32>,uint16_t> ipair) {
        std::array<uint8_t,32> overkey;
        cry::random_data(overkey);
        SKIPPED.find(ipair)-> second = overkey;
        SKIPPED.erase(ipair);
    }   

    /**
     * Compute skipped keys and save them in SKIPPED
     *
     * @param N - number in received message 
     */    
    void compute_skipped(uint16_t N) {
        while (N > Nr + 1) {
            ++Nr; 
            auto first = std::make_pair(pubkey,Nr);
            auto [newkey, deckey] = kdf_CK(CKr);
            SKIPPED.insert(std::make_pair(first,deckey));
            CKr = std::move(newkey);
        } 
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
        pubkey = pub_key;
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
     * Deserialize DRBox into actual object
     *
     * @param data - Serialized DRBox
     */
    DRBox(std::vector<uint8_t> data) {
        Decoder d{data};
        RK = d.get_arr<32>();
        CKs = d.get_arr<32>();
        CKr = d.get_arr<32>();

        // ugh
        auto eckeylen = d.get_u32();
        Encoder e;
        e.put(eckeylen);
        e.put(d.get_vec(eckeylen + 32));
        auto eckeybytes = e.move();
        DHs.load_key_binary(eckeybytes);

        Ns = d.get_u16();
        Nr = d.get_u16();
        PN = d.get_u16();
        pubkey_to_send = d.get_bool();
        pubkey = d.get_arr<32>();
        auto len = d.get_u16();
        for(uint16_t i = 0; i < len; ++i) {
            auto skipped_pubkey = d.get_arr<32>();
            auto skipped_N = d.get_u16();
            auto skipped_key = d.get_arr<32>();
            SKIPPED[{skipped_pubkey, skipped_N}] = skipped_key;
        }
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
        ++Ns;

        std::array<uint8_t, 32> key = DHs.get_bin_q();
        pubkey_to_send = false;
        Encoder e;
        e.put(create_header(key, PN, Ns));
        e.put(cry::encrypt_aes(data, {}, enckey));
        auto mackey = kdf_MAC(enckey);
        e.put(cry::mac_data(e.get(), mackey));
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
        std::array<uint8_t, 32> mac;
        std::copy(data.end() - 32, data.end(), mac.begin());
        data.resize(data.size() - 32);

        auto dcopy = data;
        auto [key, PN, N] = parse_header(data);

        auto it = SKIPPED.find(std::make_pair(key,N));

        std::array<uint8_t, 32> deckey;

        if (it == SKIPPED.end()) {  /*not skipped msg*/
            if (key != pubkey) {    /*sent new pubkey for DH-DR*/
                if (PN == Nr) {
                    DHRatchet(key);
                } else {
                    compute_skipped(PN+1);   /*some msg wwere skipped */
                    DHRatchet(key);
                }
            }

            if (N > Nr + 1) {               /*some msg were skipped*/
                compute_skipped(N);
            } else if (N < Nr + 1) {
                /*TODO error - key should be found in SKIPPED*/
            }
            std::tie(CKr, deckey) = kdf_CK(CKr);
            ++Nr;
        } else {
            deckey = it->second;
            delete_skey(std::make_pair(key,N));
        }

        if(cry::mac_data(dcopy, kdf_MAC(deckey)) != mac)
            throw std::runtime_error{"Invalid MAC."};

        return cry::decrypt_aes(data, {}, deckey);
    }

    /**
     * Serialize DRBox
     *
     * @return Byte representation of this DRBox
     */
    std::vector<uint8_t> serialize() const {
        Encoder e;
        e.put(RK);
        e.put(CKs);
        e.put(CKr);
        e.put(DHs.get_key_binary());
        e.put(static_cast<uint16_t>(Ns));
        e.put(static_cast<uint16_t>(Nr));
        e.put(static_cast<uint16_t>(PN));
        e.put(pubkey_to_send);
        e.put(pubkey);
        e.put(static_cast<uint16_t>(SKIPPED.size()));
        for(const auto& i : SKIPPED) {
            e.put(i.first.first); // message pubkey
            e.put(i.first.second); // message N
            e.put(i.second); // actual key
        }
        return e.move();
    }
};

#endif
