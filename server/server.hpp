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
#include <set>

#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;

#include "asio.hpp"
#include "../shared/messages.hpp"
#include "../shared/crypto.hpp"
#include "../shared/channel.hpp"
#include "../shared/codec.hpp"
#include "../shared/util.hpp"
#include "../shared/crybox.hpp"

class Server {
#ifdef TESTMODE
public:
    volatile bool shutdown = false;
#endif
    std::map<std::string, Channel> connections;
    std::map<std::string, std::tuple<std::array<uint8_t, 32>, std::array<uint8_t, 32>, std::vector<std::array<uint8_t, 32>>>> prekeys; // IK, SPK, OPK
    std::mutex connection_queue_mutex;
    std::deque<std::pair<std::string, Channel>> connection_queue;
    std::map<std::string, std::queue<std::vector<uint8_t>>> message_queue;
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

    /**
     * Thread-safe deletion of connections
     *
     * @param pseudonyms - Vector of pseudonyms whose connection should be released
     */
    void release_connections(const std::vector<std::string>& pseudonyms);

    /**
     * Send bytes to certain client if connected; store to message queue otherwise.
     *
     * @param pseudonym - Pseudonym of the receiver
     * @param msg - Vector of bytes to send
     */
    void send_to(const std::string& pseudonym, const std::vector<uint8_t>& msg);
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
     * GetOnline Message handler
     *
     * @param pseudonym - Originator of the message
     * @param msg - The message
     */
    void handle_get_online(const std::string& pseudonym, msg::GetOnline msg);

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
    std::set<std::string> get_connected_users();
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
#ifdef TESTMODE
    acc.non_blocking(true);
#endif
    for(;;) {
        try {
            tcp::socket sock{io_service};
#ifdef TESTMODE
            for(;;) {
                try {
                    acc.accept(sock);
                    break;
                }
                catch(std::exception& e) {
                    std::this_thread::sleep_for(std::chrono::milliseconds{100});
                }
                if(shutdown)
                    return;
            }
#else
            acc.accept(sock);
#endif

            Channel chan{std::move(sock)};
            //std::vector<uint8_t> recv_byte = chan.recv();

            auto uniq_init = message_deserializer(chan.recv());
            msg::ClientInit& init = dynamic_cast<msg::ClientInit&>(*uniq_init.get());
            init.decrypt(server_key);

            if(!init.check_mac()) {
                /* Trouble with integrity MAC*/
                std::cerr << "Trouble with integrity - MAC client init msg on server." << std::endl;
                return;
            }

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
            auto [verify_Rs, IK, SPK] = cresp.get();
            if(IK && SPK)
                prekeys[pseudonym] = {*IK, *SPK, {}};

            if(verify_Rs != Rs) {
                std::cerr << "We got a BIG problem! 'Rs != Rs'" << std::endl;
                continue; // TODO exception
            }

            chan.set_crybox(std::unique_ptr<CryBox>{new SeqBox{new AESBox{K}, new MACBox{K}}});

            if(local_key.empty() && !client_key.empty())
                store_client_key(pseudonym, client_key);

            {
                std::unique_lock lock{connection_queue_mutex};
                connection_queue.emplace_front(std::pair{pseudonym, std::move(chan)});
            }
            std::cout << pseudonym << " added to connection queue." << std::endl;
        }
        catch(std::exception& e) {
            std::cout << "Failed connection attempt (ChannelException)." << std::endl;
        }
    }
}


void Server::run() {
    auto t = std::thread(&Server::connection_handler, this);
    for(;;) {
        std::vector<std::string> dc_list;
        sync_connections();
        for(auto& c : connections) {
            auto msg = c.second.try_recv();
            if(!msg.empty()) {
                std::cout << "handling message from " << c.first << std::endl;
                handle_message(c.first, msg);
            }
            else if(!c.second.is_alive()) {
                dc_list.push_back(c.first);
            }
            else if(c.second.silence_duration().count() > 30) {
                // poke client with a stick
                msg::ReqAlive stick;
                try {
                    c.second.send(stick.serialize()); // poke
                }
                catch(ChannelException& e) {
                    dc_list.push_back(c.first);
                }
            }
        }
        release_connections(dc_list);
#ifdef TESTMODE
        if(shutdown)
            break;
#endif
    }
    t.join();
}

void Server::release_connections(const std::vector<std::string>& dcs) {
    for(auto& p : dcs) {
        connections.erase(p);
        std::cout << p << " disconnected." << std::endl;
    }
}

void Server::send_to(const std::string& pseudonym, const std::vector<uint8_t>& msg) {
    auto conn = connections.find(pseudonym);
    if(conn == connections.end() || !conn->second.is_alive()) {
        message_queue[pseudonym].push(msg);
    }
    else {
        try {
            conn->second.send(msg);
        }
        catch(ChannelException e) {
            message_queue[pseudonym].push(msg);
        }
    }
}

std::set<std::string> Server::get_connected_users() {
    std::set<std::string> connected;
    for(auto& c : connections) {
        connected.insert(c.first);
    }
    return connected;
}

void Server::handle_send(const std::string& pseudonym, msg::Send msg) {
    msg::Recv recv{pseudonym, msg.get_text()}; 
    send_to(msg.get_receiver(), recv.serialize());
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
        case msg::MessageType::GetOnline:
            handle_get_online(pseudonym, dynamic_cast<msg::GetOnline&>(*deserialized_msg.get()));
            break;
        case msg::MessageType::RespAlive:
            // client screamed, he is alive
            break;
        case msg::MessageType::Logout:
            release_connections({pseudonym});
            break;
        default:
            handle_error(*deserialized_msg.get());
    }
}

void Server::handle_get_online(const std::string& pseudonym, msg::GetOnline msg) {
    msg::RetOnline res{get_connected_users()};
    send_to(pseudonym, res.serialize());
}
#endif
