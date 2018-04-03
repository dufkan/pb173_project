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
#include <queue>
#include <thread>
#include <chrono>
#include <mutex>
#include <iterator>

#include "asio.hpp"
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

    std::mutex connection_queue_mutex;
    std::deque<std::pair<std::string, Channel>> connection_queue;


    std::map<std::string, std::queue<msg::Recv>> message_queue;

    cry::RSAKey server_key;

    msg::MessageDeserializer message_deserializer;
    asio::io_service io_service;

public:
    Server() {
        prepare_key();
    }

    /**
     * Handling of an incomming connection ~ Authentication,
     * key agreement, creation of channel.
     */
    void connection_handler() {
        using asio::ip::tcp;
        tcp::acceptor acc{io_service, tcp::endpoint(tcp::v4(), 1337)};
        for(;;) {
            tcp::socket sock{io_service};
            acc.accept(sock);

            Channel chan{std::move(sock)};

            auto [Rc, pseudonym, client_key] = decode_client_challenge(chan.recv(), server_key);

            cry::RSAKey ck;
            ck.import(client_key);

            std::array<uint8_t, 32> Rs;
            cry::random_data(Rs);

            chan.send(server_chr(Rs, Rc, ck));

            Encoder e;
            e.put(Rs);
            e.put(Rc);
            auto K = cry::hash_sha(e.move());

            std::array<uint8_t, 32> verify_Rs = decode_client_response(chan.recv(), K);

            if(verify_Rs != Rs) {
                std::cerr << "We got a BIG problem!" << std::endl;
                continue; // TODO exception
            }

            chan.set_key(K);
            {
                std::unique_lock lock{connection_queue_mutex};
                connection_queue.emplace_front(std::pair{pseudonym, std::move(chan)});
            }
            std::cout << pseudonym << " added to connection queue." << std::endl;
        }
    }

    void sync_connections() {
        std::unique_lock lock{connection_queue_mutex, std::try_to_lock};
        if(!lock.owns_lock())
            return;
        connections.insert(std::move_iterator(connection_queue.begin()), std::move_iterator(connection_queue.end()));
        while(!connection_queue.empty()) {
            connection_queue.pop_front();
        }
    }

    void run() {
        auto t = std::thread(&Server::connection_handler, this);
        for(;;) {
            sync_connections();
            for(auto& c : connections) {
                auto msg = c.second.try_recv();
                if(!msg.empty()) {
                    std::cout << "handling message from " << c.first << std::endl;
                    handle_message(c.first, msg);
                }
            }
        }
        t.join();
    }

    std::vector<std::string> get_connected_users() {
        std::vector<std::string> connected;
        connected.reserve(connections.size());
        for(auto& c : connections) {
            connected.push_back(c.first);
        }
        return connected;
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

    void handle_send(const std::string& pseudonym, msg::Send msg) {
        auto conn = connections.find(msg.get_receiver());
        msg::Recv recv{pseudonym, msg.get_text()};
        if(conn == connections.end()) {
            message_queue[msg.get_receiver()].push(recv);
        }
        else {
            // send to user
        }
    }

    void handle_error(msg::Message msg) {
        std::cerr << "Got a message I cannot handle." << std::endl;
    }

    void handle_message(const std::string& pseudonym, std::vector<uint8_t> msg) {
        std::unique_ptr<msg::Message> deserialized_msg = message_deserializer.deserialize(msg);
        switch(msg::type(msg)) {
            case msg::MessageType::Send:
                handle_send(pseudonym, dynamic_cast<msg::Send&>(*deserialized_msg.get()));
                break;
            default:
                handle_error(*deserialized_msg.get());
        }
    }

    void prepare_key() {
        try {
            std::vector<uint8_t> file_key = util::read_file("TOPSECRET");
            server_key.import(file_key);
        }
        catch(const std::ios_base::failure& e) {
            cry::generate_rsa_keys(server_key, server_key);
            util::write_file("TOPSECRET", server_key.export_all());
            util::write_file("PUBSECRET", server_key.export_pub());
        }
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
