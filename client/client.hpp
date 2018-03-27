#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <vector>
#include <string>

#include "asio.hpp"
#include "../shared/messages.hpp"
#include "../shared/channel.hpp"
#include "../shared/crypto.hpp"
#include "../shared/codec.hpp"

class Client {
#ifdef TESTMODE
public:
#endif
    Channel chan;

    std::vector<uint8_t> client_challenge(std::array<uint8_t, 32> Rc, cry::RSAKey& rsa_pub, std::string pseudo, std::vector<uint8_t> key) {
        Encoder e;
        std::vector<uint8_t> eRc = cry::encrypt_rsa(Rc, rsa_pub);

        e.put(static_cast<uint16_t>(pseudo.size()));
        e.put(pseudo);
        e.put(static_cast<uint16_t>(key.size()));
        e.put(key);

        std::vector<uint8_t> payload = e.move();
        std::vector<uint8_t> ePayload = cry::encrypt_aes(payload, {}, Rc);

        e.put(eRc);
        e.put(ePayload);

        return e.move();
    }

    std::vector<uint8_t> client_response(std::array<uint8_t, 32> K,  std::array<uint8_t, 32> Rs) {
        std::vector<uint8_t> msg = cry::encrypt_aes(Rs, {}, K);
        return msg;
    }

    std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 32>> decode_server_chr(const std::vector<uint8_t>& msg, cry::RSAKey& priv_key) {
        Decoder d{msg};
        auto eRs = d.get_vec(512);
        auto epayload = d.get_vec();

        std::vector<uint8_t> dRs = cry::decrypt_rsa(eRs, priv_key);
        std::array<uint8_t, 32> Rs;
        std::copy(dRs.data(), dRs.data() + 32, Rs.data());

        std::vector<uint8_t> dpayload = cry::decrypt_aes(epayload, {}, Rs);
        d = dpayload; // copy assignment hopefully
        std::vector<uint8_t> tmp = d.get_vec();
        std::array<uint8_t, 32> verify_Rc;
        std::copy(tmp.data(), tmp.data() + 32, verify_Rc.data());

        return {Rs, verify_Rc};
    }

public:
    /**
     * Initiate a connection to server
     */
    void initiate_connection() {
        // generate Rc
        // encrypt Rc using pub_key_server
        // encrypt pseudonym and possibly pubkey using Rc
        // compute HMAC
        // form message
        // send message
        // recieve response
        // decrypt Rs using privkey
        // decrypt Rc using Rs and verify it
        // compute K = sha(Rs || Rc)
        // encrypt Rs using K and send it to server
        // initialize Channel with key K
    }
};

/**
 * Create message - for choosed pseudonym write the text of message.
 * 
 * @param pseudonym - pseudonym of the reciever
 */
//msg::Message write_message(std::string pseudonym);

/**
 * Receives a message from connection.
 *
 * @param conn - connection to recieve message from
 */
//std::vector<uint8_t> recv_message(/* asio::tcp::connection& conn */);


/**
 * Sends a message to connection.
 *
 * @param conn - connection to send to
 */
//void send_message(/* asio::tcp::connection& conn */, msg::Message& message);



/**
 * Add new user to database my_friends.
 *
 * @param pseudonym - pseudonym of the user
 * @param pubkey - public key of the user
 */
//void add_friend(std::string psuedonym, std::vector<uint_8> pubkey);


/**
 * Get a user public key from database my_frinds. 
 *
 * @param pseudonym - pseudonym of the user
 */
//std::vector<uint_8> get_friend_pubkey(std::string pseudonym);


/**
 * Generate new pair of public and private key.
 *
 * @param prikey - the new private key will be saved here
 * @param pubkey - the new public key will be saved here
 */
//void generate_keys(std::vector<uint_8> prikey, std::vector<uint_8> pubkey);


/**
 * Ask server for public key of the user
 * 
 * @param pseudonym - pseudonym of the user
 * @return user public key
 */
//std::vector<uint_8> ask_user_pubkey(std::string pseudonym);

/**
 * Create challenge message for challenge-response protocol with server.
 *
 * @param pubkey - public key to use for challenge encryption
 */
//msg::Challenge create_challenge(std::vector<uint8_t> pubkey);


/**
 * Create response message for challenge-response protocol with server.
 *
 * @param challenge Received challenge
 * @param pubkey Public key of the response recipient
 */
//msg::Response create_response(std::vector<uint8_t> challenge, std::vector<uint8_t> pubkey);


/**
 * Get key from the challenge response messeges.
 *
 * @param chall - data from challenge
 * @param resp - data from response
 * @return symetric key created from chall and resp
 */ 
//std::vector<uint_8> chr_create_key(std::vector<uint_8> chall, std::vector<uint_8> resp);


/**
 * Close connection.
 *
 * @param conn - connection which should be closed
 */
//void close_connection(/*asio::tcp::connection& conn*/);
#endif
