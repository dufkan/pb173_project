#ifndef SERVER_HPP
#define SERVER_HPP

#include <vector>
#include <string>
#include <iostream>
#include <cstdio>
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

#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;

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

    /**
     * Load server key
     *
     * If the key file doesn't exist, creates it first.
     */
    void prepare_key();

    /**
     * Load client key from local file
     *
     * @return Byte representation of the key; or an empty vector if file does not exist
     */
    static std::vector<uint8_t> load_client_key(const std::string& pseudonym);

    /**
     * Store client key in local file
     *
     * @param pseudonym - Pseudonym of the user, the key is from
     * @param key - Byte representation of the key
     * @return true if the key for pseudonym didn't exist and was successfully created; false otherwise
     */
    static bool store_client_key(const std::string& pseudonym, const std::vector<uint8_t>& key);

    /**
     * Remove client key
     *
     * @param pseudonym - Pseudonym of the owner of the key
     * @return true if succeded; false otherwise
     */
    static bool remove_client_key(const std::string& pseudonym);

    /**
     * Thread-safe synchronization of incoming connections with connected users
     */
    void sync_connections();
public:
    Server();

    /**
     * Run the server loop
     */
    void run();

    /**
     * Handle incoming network connection
     */
    void connection_handler();

    /**
     * Handle incomming message
     *
     * Deserializes message and passes it to appropriate message handler.
     *
     * @param pseudonym - Originator of the message
     * @param msg - Byte representation of the message
     */
    void handle_message(const std::string& pseudonym, std::vector<uint8_t> msg);

    /**
     * Send Message handler
     *
     * @param pseudonym - Originator of the message
     * @param msg - The message
     */
    void handle_send(const std::string& pseudonym, msg::Send msg);

    /**
     * Message error handler
     *
     * Invoked if the message was not handled by any other handler.
     *
     * @param msg - The message
     */
    void handle_error(msg::Message msg);

    /**
     * Get vector of pseudonyms of connected users
     *
     * @return Vector of pseudonyms of connected users
     */
    std::vector<std::string> get_connected_users();
};

void Server::prepare_key() {
    try {
        std::vector<uint8_t> file_key = util::read_file("TOPSECRET");
        server_key.import(file_key);
    }
    catch(std::ios_base::failure& e) {
        cry::generate_rsa_keys(server_key, server_key);
        util::write_file("TOPSECRET", server_key.export_all());
        util::write_file("PUBSECRET", server_key.export_pub());
    }
}

std::vector<uint8_t> Server::load_client_key(const std::string& pseudonym) {
    if(!fs::exists("keys/" + pseudonym))
        return {};
    return util::read_file("keys/" + pseudonym);
}

bool Server::store_client_key(const std::string& pseudonym, const std::vector<uint8_t>& key) {
    if(!fs::is_directory("keys"))
        fs::create_directory("keys");
    if(fs::exists("keys/" + pseudonym))
        return false;
    util::write_file("keys/" + pseudonym, key);
    return true;
}

bool Server::remove_client_key(const std::string& pseudonym) {
    std::string path = "keys/" + pseudonym;
    return std::remove(path.c_str()) == 0;
}

void Server::sync_connections() {
    std::unique_lock lock{connection_queue_mutex, std::try_to_lock};
    if(!lock.owns_lock())
        return;
    connections.insert(std::move_iterator(connection_queue.begin()), std::move_iterator(connection_queue.end()));
    while(!connection_queue.empty()) {
        connection_queue.pop_front();
    }
}

Server::Server() {
    prepare_key();
}

void Server::connection_handler() {
    using asio::ip::tcp;
    tcp::acceptor acc{io_service, tcp::endpoint(tcp::v4(), 1337)};
    for(;;) {
        tcp::socket sock{io_service};
        acc.accept(sock);

        Channel chan{std::move(sock)};

        auto uniq_init = message_deserializer(chan.recv());
        msg::ClientInit& init = dynamic_cast<msg::ClientInit&>(*uniq_init.get());
        init.decrypt(server_key);
        auto [Rc, pseudonym, client_key] = init.get();

        cry::RSAKey ck;
        std::vector<uint8_t> local_key = load_client_key(pseudonym);
        if(!local_key.empty())
            ck.import(local_key);
        else if(!client_key.empty())
            ck.import(client_key);
        else
            continue; // TODO handle no key

        std::array<uint8_t, 32> Rs;
        cry::random_data(Rs);

        msg::ServerResp sresp{Rs, Rc};
        sresp.encrypt(ck);
        chan.send(sresp);

        Encoder e;
        e.put(Rs);
        e.put(Rc);
        auto K = cry::hash_sha(e.move());

        auto uniq_cresp = message_deserializer(chan.recv());
        msg::ClientResp& cresp = dynamic_cast<msg::ClientResp&>(*uniq_cresp.get());
        cresp.decrypt(K);
        std::array<uint8_t, 32> verify_Rs = cresp.get();

        if(verify_Rs != Rs) {
            std::cerr << "We got a BIG problem!" << std::endl;
            continue; // TODO exception
        }

        chan.set_key(K);

        if(local_key.empty() && !client_key.empty())
            store_client_key(pseudonym, client_key);

        {
            std::unique_lock lock{connection_queue_mutex};
            connection_queue.emplace_front(std::pair{pseudonym, std::move(chan)});
        }
        std::cout << pseudonym << " added to connection queue." << std::endl;
    }
}


void Server::run() {
    auto t = std::thread(&Server::connection_handler, this);
    for(;;) {
        sync_connections();
        for(auto& c : connections) {
            auto msg = c.second.try_recv();
            if(!msg.empty()) {
                std::cout << "handling message from " << c.first << std::endl;
                handle_message(c.first, msg);
            }
            // TODO handle disconnects
        }
    }
    t.join();
}

std::vector<std::string> Server::get_connected_users() {
    std::vector<std::string> connected;
    connected.reserve(connections.size());
    for(auto& c : connections) {
        connected.push_back(c.first);
    }
    return connected;
}

void Server::handle_send(const std::string& pseudonym, msg::Send msg) {
    auto conn = connections.find(msg.get_receiver());
    msg::Recv recv{pseudonym, msg.get_text()};
    if(conn == connections.end()) {
        message_queue[msg.get_receiver()].push(recv);
    }
    else {
        conn->second.send(msg::Recv{pseudonym, msg.get_text()});
    }
}

void Server::handle_error(msg::Message msg) {
    std::cerr << "Got a message I cannot handle." << std::endl;
}

void Server::handle_message(const std::string& pseudonym, std::vector<uint8_t> msg) {
    std::unique_ptr<msg::Message> deserialized_msg = message_deserializer(msg);
    switch(msg::type(msg)) {
        case msg::MessageType::Send:
            handle_send(pseudonym, dynamic_cast<msg::Send&>(*deserialized_msg.get()));
            break;
        default:
            handle_error(*deserialized_msg.get());
    }
}
#endif
