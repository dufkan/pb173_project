#ifndef SERVER_HPP
#define SERVER_HPP

#include <vector>
#include <string>
#include <iostream>
#include <iterator>
#include <fstream>
#include <map>
#include <cstdio>
#include <utility>

//#include "asio.hpp"
#include "../shared/messages.hpp"
#include "../shared/crypto.hpp"
#include "../shared/channel.hpp"
#include "../shared/codec.hpp"
#include "../shared/util.hpp"

class Server {
#ifdef TESTMODE
public:
#endif
    std::map<std::string, Channel> connections;
public:
    std::vector<std::string> get_connected_users() {
        std::vector<std::string> connected;
        connected.reserve(connections.size());
        for(auto& c : connections) {
            connected.push_back(c.first);
        }
        return connected;
    }

    /**
     * Handling of an incomming connection ~ Authentication,
     * key agreement, creation of channel.
     */
    void handle_new_connection() {
    }

    std::vector<uint8_t> server_chr(std::array<uint8_t, 32> Rs, std::array<uint8_t, 32> Rc,  cry::RSAKey& rsa_pub) {
        Encoder e;
        std::vector<uint8_t> eRs = cry::encrypt_rsa(Rs, rsa_pub);
        std::vector<uint8_t> eRc = cry::encrypt_aes(Rc, {}, Rs);

        e.put(eRs);
        e.put(eRc);

        return e.move();
    }

    std::tuple<std::array<uint8_t, 32>, std::string, std::vector<uint8_t>> decode_client_challenge(const std::vector<uint8_t>& msg, cry::RSAKey& rsa_priv) {
        Decoder d{msg};
        std::vector<uint8_t> eRc = d.get_vec(512);
        std::vector<uint8_t> epayload = d.get_vec();

        std::vector<uint8_t> dRc = cry::decrypt_rsa(eRc, rsa_priv);
        std::array<uint8_t, 32> Rc;
        std::copy(dRc.data(), dRc.data() + 32, Rc.data());

        auto dpayload = cry::decrypt_aes(epayload, {}, Rc);
        d = dpayload; // copy assignment hopefully
        auto plen = d.get_u16();
        auto pseudonym = d.get_str(plen);
        auto klen = d.get_u16();
        auto key = d.get_vec(klen);

        return {Rc, pseudonym, key};
    }

    std::array<uint8_t, 32> decode_client_response(const std::vector<uint8_t>& msg, const std::array<uint8_t, 32>& K) {
        auto ok = cry::decrypt_aes(msg, {}, K);
        std::array<uint8_t, 32> verify_Rs;
        std::copy(ok.data(), ok.data() + 32, verify_Rs.data());
        return verify_Rs;
    }

};

/**
 * Starts server ~ listening on TCP ip:port.
 *
 * @param ip IP address of the server
 * @param port TCP port of the server
 */
//void server(/* ip */, /* port */);

/**
 * Accepts a connection from acceptor
 *
 * @param acceptor Acceptor object listening to connections.
 */
//void accept_connection(/* asio::tcp::acceptor& acceptor */);

/**
 * Receives a message from connection.
 *
 * @param conn Connection to recieve message from
 *
 * @return Vector of bytes of received message
 */
//std::vector<uint8_t> recv_message(/* asio::tcp::connection& conn */);

/**
 * Sends a message to connection.
 *
 * @param conn Connection to send to
 */
//void send_message(/* asio::tcp::connection& conn */, msg::Message& message);


/**
 * Add new user to database.
 *
 * @param pseudonym Pseudonym of the user
 * @param pubkey Public key of the user
 * @return False if user already exists; true otherwise
 */
bool add_user(std::string pseudonym, std::vector<uint8_t> pubkey) {
    std::ifstream ifs{pseudonym};
    if(ifs.good())
        return false;

    ifs.close();

    util::write_file(pseudonym, pubkey);
    return true;
}

/**
 * Remove user from the database.
 *
 * @param pseudonym Pseudonym of the user
 * @return True if operation succeded; false otherwise
 */
bool remove_user(std::string pseudonym) {
    return !std::remove(pseudonym.c_str());
}

/**
 * Get user information from database.
 *
 * @param pseudonym Pseudonym of the user
 *
 * @return Information about the user (public key)
 */
std::vector<uint8_t> get_user(std::string pseudonym) {
    return util::read_file(pseudonym);
}

#endif
