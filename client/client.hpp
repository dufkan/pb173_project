#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <vector>
#include <string>
#include <iostream>

#include "asio.hpp"
#include "../shared/messages.hpp"
#include "../shared/channel.hpp"
#include "../shared/crypto.hpp"
#include "../shared/codec.hpp"
#include "../shared/util.hpp"

class Client {
#ifdef TESTMODE
public:
#endif
    Channel chan;
    std::map<std::string, std::array<uint8_t,32>> contacts;

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

    /**
     * Create message Send from params and encrypt the text with AES-256 recv_key
     *
     * @param recv_name Pseudonym of reciever of the message
     * @param recv_key Symetric key for AES shared with reciever of the message
     * @param text Text of the message
     *
     * @return message Send
     */
    msg::Send create_message(std::string recv_name, std::vector<uint8_t> text) {
	auto it = contacts.find(recv_name);
	if (it == contacts.end()) {
	    /* Send a message to server fot recv keys and prekeys.... */

	}
	std::array<uint8_t,32> recv_key = it->second;
	std::vector text_enc = encrypt_aes(text, {}, recv_key);
        msg::Send msg_send(recv_name,text_enc);
        return msg_send.move();
    }


public:
    void run() {
        using asio::ip::tcp;
        asio::io_service io_service;

        tcp::socket sock{io_service};
        tcp::resolver resolver{io_service};
        asio::connect(sock, resolver.resolve({"127.0.0.1", "1337"}));

        Channel chan{std::move(sock)};
        initiate_connection(chan);
    }

    /**
     * Initiate a connection to server
     */
    void initiate_connection(Channel& chan) {
        std::vector<uint8_t> file_key = util::read_file("PUBSECRET");
        cry::RSAKey spub;
        spub.import(file_key);

        std::array<uint8_t, 32> Rc;
        cry::random_data(Rc);

        cry::RSAKey ckey;
        cry::generate_rsa_keys(ckey, ckey);

        std::vector<uint8_t> chall = client_challenge(Rc, spub, "alice", ckey.export_pub());
        chan.send(chall);

        auto [Rs, verify_Rc] = decode_server_chr(chan.recv(), ckey);

        if(verify_Rc != Rc) {
            std::cerr << "There is a BIG problem!" << std::endl;
            return; // TODO handle with exception
        }

        Encoder e;
        e.put(Rs);
        e.put(Rc);
        std::array<uint8_t, 32> K = cry::hash_sha(e.move());

        chan.send(client_response(K, Rs));

        chan.set_key(K);
        std::cout << "I am in!" << std::endl;
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
