#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <vector>
#include <string>
#include <iostream>
#include <map>

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
    std::map<std::string, std::array<uint8_t,32>> contacts;
    std::string pseudonym = "noone";

    msg::MessageDeserializer message_deserializer;

    std::vector<uint8_t> client_challenge(std::array<uint8_t, 32> Rc, cry::RSAKey& rsa_pub, std::string pseudo, std::vector<uint8_t> key) {
        msg::ClientInit message{pseudo, Rc, key};
        message.encrypt(rsa_pub);
        return message.serialize();
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
    msg::Send create_message(std::string recv_name, std::array<uint8_t,32> recv_key, std::vector<uint8_t> text) {
	std::vector text_enc = cry::encrypt_aes(text, {}, recv_key);
        msg::Send msg_send(recv_name,text_enc);
        return msg_send;
    }



    /**
     * Send message text to client recv_name to channel
     *
     * @param recv_name Reciever name
     * @param text Text of the message
     */
    void send_message(std::string recv_name, std::string text, Channel& chan){
        std::vector<uint8_t> text_u(text.begin(), text.end());
        auto it = contacts.find(recv_name);
        if (it == contacts.end()) {
            /* Send a message to server fot recv keys and prekeys.... */

        }
        std::array<uint8_t,32> recv_key = it->second; 	
	msg::Send msg_send = create_message(recv_name, recv_key, text_u);
	chan.send(msg_send.serialize());
    }
    
    
    /**
     * Decrypt text of message in message Recv
     * 
     * @param msg_recv Recieved message
     * @return Pair (sender_name, decrypted_text)
     */

    std::pair<std::string,std::vector<uint8_t>> decrypt_msg(msg::Recv& msg_recv) {
	std::string sender_name = msg_recv.get_sender();
	auto it = contacts.find(sender_name);
        if (it == contacts.end()) {
            /* Some error or resolution of it */

        }
	std::vector<uint8_t> text_dec = cry::decrypt_aes(msg_recv.get_text(),{},it->second);
	return std::make_pair(sender_name,text_dec);
    }


    /**
     * From recived vytes get get the sender and the text of message
     *
     * @param msg_u Recieved bytes
     * @return Pair(sender_name, text_of_message) 
     */

    std::pair<std::string,std::string> handle_recv_msg(std::vector<uint8_t> msg_u) {
	std::unique_ptr<msg::Message> msg_des = msg::Recv::deserialize(msg_u);
	msg::Recv& recv_des = dynamic_cast<msg::Recv&>(*msg_des.get());
	auto sender_text = decrypt_msg(recv_des);
	std::string text_s(reinterpret_cast<char*> (sender_text.second.data()),sender_text.second.size());
	return std::make_pair(sender_text.first,text_s);
    }

public:
    Client() = default;
    Client(std::string pseudonym): pseudonym(std::move(pseudonym)) {}

    bool add_contact(std::string name, std::array<uint8_t,32> key) {
        auto it = contacts.find(name);
	if (it != contacts.end()) {
		return false;
	}
	contacts[name]=key;
	return true;
    }
    
    std::array<uint8_t,32> get_key(std::string name) {
	return contacts[name];
    }


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

        msg::ClientInit init{pseudonym, Rc, ckey.export_pub()};
        init.encrypt(spub);
        chan.send(init);

        auto uniq_sresp = message_deserializer(chan.recv());
        auto sresp = dynamic_cast<msg::ServerResp&>(*uniq_sresp.get());
        sresp.decrypt(ckey);
        auto [Rs, verify_Rc] = sresp.get();

        if(verify_Rc != Rc) {
            std::cerr << "There is a BIG problem!" << std::endl;
            return; // TODO handle with exception
        }

        Encoder e;
        e.put(Rs);
        e.put(Rc);
        std::array<uint8_t, 32> K = cry::hash_sha(e.move());

        msg::ClientResp cresp{Rs};
        cresp.encrypt(K);
        chan.send(cresp);

        chan.set_key(K);
        std::cout << "I am in!" << std::endl;
    }
};
#endif
