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
#include <deque>
#include <thread>
#include <chrono>
#include <mutex>
#include <iterator>
#include <set>

#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
using key32 = std::array<uint8_t, 32>;

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
    std::map<std::string, std::tuple<key32, key32, std::vector<std::pair<uint16_t, key32>>, std::array<uint8_t,512>, std::vector<uint8_t>>> prekeys; // IK, SPK, OPK, signature, RSAsig
    std::mutex connection_queue_mutex;
    std::deque<std::pair<std::string, Channel>> connection_queue;
    std::map<std::string, std::deque<std::vector<uint8_t>>> message_queue;
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
     * Load client prekeys
     */
    void prepare_prekeys();

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
     *
     * @return vector of newly connected users
     */
    std::vector<std::string> sync_connections();

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

    /**
     * Store prekeys of certain client
     *
     * @param pseudonym - Pseudonym
     * @param IK - Identity key
     * @param SPK - Signed Prekey
     * @param OPKs - Vector of one-time prekeys with assigned ids
     */
    static void store_prekeys(const std::string& pseudonym, key32 IK, key32 SPK, std::vector<std::pair<uint16_t, key32>> OPKs, std::array<uint8_t, 512> sign, std::vector<uint8_t> signing_key);

    /**
     * Load prekeys of certain client from local file
     *
     * @param pseudonym - Name of the Client
     * @returns The ALL-IN-ONE bundle!
     */
    static std::tuple<key32, key32, std::vector<std::pair<uint16_t, key32>>, std::array<uint8_t,512>, std::vector<uint8_t>> load_prekeys(const std::string& pseudonym);
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
     * Handle x3dh init message
     *
     * Deserializes massage, changes pseudonym and send
     *
     * @param pseudonym - client who sends x3dh message
     * @param msg - Byte representation of the message
     */

    void handle_x3dh_init(const std::string& pseudonym, msg::X3dhInit msg);

    /**
     * Send Message handler
     *
     * @param pseudonym - Originator of the message
     * @param msg - The message
     */
    void handle_send(const std::string& pseudonym, const msg::Send& msg);

    /**
     * GetOnline Message handler
     *
     * @param pseudonym - Originator of the message
     * @param msg - The message
     */
    void handle_get_online(const std::string& pseudonym, msg::GetOnline msg);

    /**
     * AskPrekey Message handler
     *
     * @param pseudonym - Originator of the message
     * @param msg - The message
     */
    void handle_ask_prekey(const std::string& pseudonym, const msg::AskPrekey& msg);

    /**
     * UploadPrekey Message handler
     *
     * @param pseudonym - Originator of the message
     * @param msg - The message
     */
    void handle_upload_prekey(const std::string& pseudonym, const msg::UploadPrekey& msg);

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

std::vector<std::string> Server::sync_connections() {
    std::unique_lock lock{connection_queue_mutex, std::try_to_lock};
    if(!lock.owns_lock())
        return {};
    std::vector<std::string> conlist;
    for(auto& c : connection_queue)
        conlist.push_back(c.first);

    connections.insert(std::move_iterator(connection_queue.begin()), std::move_iterator(connection_queue.end()));

    while(!connection_queue.empty()) {
        connection_queue.pop_front();
    }

    return conlist;
}

Server::Server() {
    prepare_key();
    prepare_prekeys();
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

            auto uniq_init = message_deserializer(chan.recv());
            msg::ClientInit& init = dynamic_cast<msg::ClientInit&>(*uniq_init.get());
            init.decrypt(server_key);

            if(!init.check_mac()) {
                throw std::runtime_error{"Trouble with integrity - MAC is not right."};
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
            auto [sign, signing_key] = cresp.get_sign_and_key();
            if(verify_Rs != Rs) {
                throw std::runtime_error{"Client response is not OK."};
                continue; 
            }

            chan.set_crybox(std::unique_ptr<CryBox>{new SeqBox{new AESBox{K}, new MACBox{K}}});

            if(IK && SPK && sign && signing_key) {
                prekeys[pseudonym] = {*IK, *SPK, {}, *sign, *signing_key};
                store_prekeys(pseudonym, *IK, *SPK, {}, *sign, *signing_key);
            }

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
        auto newlings = sync_connections();
        for(auto n : newlings) {
            auto nmsgq = message_queue.find(n);
            if(nmsgq != message_queue.end()) {
                for(auto m : nmsgq->second)
                    send_to(n, m);
                nmsgq->second.clear();
            }
        }
        for(auto& c : connections) {
            auto msg = c.second.try_recv();
            if(!msg.empty()) {
                std::cout << "handling message from " << c.first << std::endl;
                handle_message(c.first, msg);
            }
            else if(!c.second.is_alive()) {
                dc_list.push_back(c.first);
            }
            else if(std::get<2>(prekeys[c.first]).size() < 1) {
                if(c.second.silence_duration().count() > 5)
                    send_to(c.first, msg::ReqPrekey{}.serialize());
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
        message_queue[pseudonym].push_back(msg);
    }
    else {
        try {
            conn->second.send(msg);
        }
        catch(ChannelException& e) {
            message_queue[pseudonym].push_back(msg);
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

void Server::handle_send(const std::string& pseudonym, const msg::Send& msg) {
    msg::Recv recv{pseudonym, msg.get_text()}; 
    send_to(msg.get_receiver(), recv.serialize());
}


void Server::handle_error([[maybe_unused]] msg::Message msg) {
    std::cerr << "Got a message I cannot handle." << std::endl;
}

void Server::handle_message(const std::string& pseudonym, [[maybe_unused]] std::vector<uint8_t> msg) {
    std::unique_ptr<msg::Message> deserialized_msg = message_deserializer(msg);
    switch(msg::type(msg)) {
        case msg::MessageType::Send:
            handle_send(pseudonym, dynamic_cast<msg::Send&>(*deserialized_msg.get()));
            break;
        case msg::MessageType::GetOnline:
            handle_get_online(pseudonym, dynamic_cast<msg::GetOnline&>(*deserialized_msg.get()));
            break;
        case msg::MessageType::AskPrekey:
            handle_ask_prekey(pseudonym, dynamic_cast<msg::AskPrekey&>(*deserialized_msg.get()));
            break;
        case msg::MessageType::UploadPrekey:
            handle_upload_prekey(pseudonym, dynamic_cast<msg::UploadPrekey&>(*deserialized_msg.get()));
            break;
        case msg::MessageType::RespAlive:
            // client screamed, he is alive
            break;
        case msg::MessageType::Logout:
            release_connections({pseudonym});
            break;
        case msg::MessageType::X3dhInit:
            handle_x3dh_init(pseudonym, dynamic_cast<msg::X3dhInit&>(*deserialized_msg.get()));
            break;
        default:
            handle_error(*deserialized_msg.get());
    }
}

void Server::handle_get_online(const std::string& pseudonym, [[maybe_unused]]  msg::GetOnline msg) {
    msg::RetOnline res{get_connected_users()};
    send_to(pseudonym, res.serialize());
}

void Server::handle_x3dh_init(const std::string& pseudonym, msg::X3dhInit msg) {
    std::string recv = msg.get_name();
    msg.change_name(pseudonym);
    std::cout << "Handling x3dh init msg" << std::endl;
    send_to(recv, msg.serialize());
}

void Server::handle_ask_prekey(const std::string& pseudonym, const msg::AskPrekey& msg) {
    auto pks = prekeys.find(msg.get_pseudonym());
    if(pks == prekeys.end());
    else {
        auto& [IK, SPK, OPKs, sign, rsak] = pks->second;
        uint16_t id = 0;
        std::array<uint8_t, 32> OPK{};
        if(!OPKs.empty()) {
            std::tie(id, OPK) = OPKs.back();
            OPKs.pop_back();
            store_prekeys(pks->first, std::get<0>(pks->second), std::get<1>(pks->second), std::get<2>(pks->second), std::get<3>(pks->second), std::get<4>(pks->second));
        }
        send_to(pseudonym, msg::RetPrekey{msg.get_pseudonym(), id, OPK, IK, SPK, sign, rsak}.serialize());
    }
}

void Server::handle_upload_prekey(const std::string& pseudonym, const msg::UploadPrekey& msg) {
    std::get<2>(prekeys[pseudonym]).push_back(msg.get());
}

void Server::store_prekeys(const std::string& pseudonym, key32 IK, key32 SPK, std::vector<std::pair<uint16_t, key32>> OPKs, std::array<uint8_t, 512> sign, std::vector<uint8_t> signing_key) {
    Encoder e;
    e.put(IK);
    e.put(SPK);
    e.put(sign);
    e.put(static_cast<uint16_t>(signing_key.size()));
    e.put(signing_key);
    e.put(static_cast<uint16_t>(OPKs.size()));
    for(auto& [id, OPK] : OPKs) {
        e.put(id);
        e.put(OPK);
    }
    util::write_file("prekeys/" + pseudonym, e.move());
}

std::tuple<key32, key32, std::vector<std::pair<uint16_t, key32>>, std::array<uint8_t,512>, std::vector<uint8_t>> Server::load_prekeys(const std::string& pseudonym) {
    Decoder d{util::read_file("prekeys/" + pseudonym)};
    auto IK = d.get_arr<32>();
    auto SPK = d.get_arr<32>();
    auto sign = d.get_arr<512>();
    auto len = d.get_u16();
    auto signing_key = d.get_vec(len);
    auto OPKslen = d.get_u16();
    std::vector<std::pair<uint16_t, key32>> OPKs;
    for(uint16_t i = 0; i < OPKslen; ++i) {
        auto id = d.get_u16();
        auto OPK = d.get_arr<32>();
        OPKs.push_back({id, OPK});
    }
    return {IK, SPK, std::move(OPKs), sign, signing_key};
}

void Server::prepare_prekeys() {
    for(auto& c: fs::directory_iterator("prekeys"))
        prekeys[c.path().filename()] = load_prekeys(c.path().filename());
}
#endif
