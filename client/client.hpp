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

    /**
     * Create message Send from params and encrypt the text with AES-256 recv_key
     *
     * @param recv_name Pseudonym of reciever of the message
     * @param recv_key Symetric key for AES shared with reciever of the message
     * @param text Text of the message
     *
     * @return message Send
     */
    msg::Send create_message(std::string recv_name, std::array<uint8_t, 32> recv_key, std::vector<uint8_t> text); 



    /**
     * Send message text to client recv_name to channel
     *
     * @param recv_name Reciever name
     * @param text Text of the message
     */
    void send_message(std::string recv_name, std::string text, Channel& chan);

   
    /**
     * Load psuedonym of the reciever
     *
     * @param recv_name
     * @return true if recv_name is in conntacs
     */
    bool load_recv(std::string recv_name);


    /**
     * Load text of the message from user
     * 
     * @return the text
     */
    std::string load_text_message();


    /**
     * Sending message with the params from user std::in
     *
     * @param chan - Channel
     */
    void ui_send_message(Channel& chan);



    /**
     * Decrypt text of message in message Recv
     *
     * @param msg_recv Recieved message
     * @return Pair (sender_name, decrypted_text)
     */
    std::pair<std::string, std::vector<uint8_t>> decrypt_msg(msg::Recv& msg_recv); 



    /**
     * From recived bytes get get the sender and the text of message
     *
     * @param msg_u Recieved bytes
     * @return Pair(sender_name, text_of_message) 
     */
    std::pair<std::string,std::string> handle_recv_msg(std::vector<uint8_t> msg_u);


    /**
     * From received bytes write to user name of the sender and text of the message
     *
     */
    void ui_recv_message(std::vector<uint8_t> msg);

public:
    Client() = default;
    Client(std::string pseudonym): pseudonym(std::move(pseudonym)) {}

    /**
     * Save psuedonym and key to cantacts
     *
     * @param name Pseudonym
     * @param key Key
     * @return true is everything is OK, false is the contact is already saved
     */
    bool add_contact(std::string name, std::array<uint8_t,32> key);


    /**
     * Get key for pseudonym from saved contacts
     *
     * @param name Pseudonym
     * @return key
     */
    std::array<uint8_t,32> get_key(std::string name);



    /**
     * Load key from file
     *
     * @return Key
     */
    std::vector<uint8_t> load_key();


    /**
     * Write key in file
     * 
     * @param key
     */
    void write_key(std::vector<uint8_t>& key);


    /**
     * Run connection
     * test version
     */
    void run();


    /**
     * Initiate a connection to server
     *
     * @param chan - Channel
     */
    void initiate_connection(Channel& chan);

}; //Client


msg::Send Client::create_message(std::string recv_name, std::array<uint8_t, 32> recv_key, std::vector<uint8_t> text) {
        std::vector text_enc = cry::encrypt_aes(text, {}, recv_key);
        msg::Send msg_send(recv_name,text_enc);
        return msg_send;
}



void Client::send_message(std::string recv_name, std::string text, Channel& chan){
        std::vector<uint8_t> text_u(text.begin(), text.end());
        auto it = contacts.find(recv_name);
        if (it == contacts.end()) {
            /* Send a message to server fot recv keys and prekeys.... */
	    /*Is this checking for the second time needed?*/
        }
        std::array<uint8_t, 32> recv_key = it->second;
        msg::Send msg_send = create_message(recv_name, recv_key, text_u);
        chan.send(msg_send);
    }



bool Client::load_recv(std::string recv_name) {
	std::cout << "Reciever - pseudonym: ";
	std::getline(std::cin,recv_name);
	auto it = contacts.find(recv_name);
	return (it!=contacts.end());    
    }


std::string Client::load_text_message() {
	std::string stext;
	std::cout << "Text of the message: ";
	std::getline(std::cin,stext);
	return std::move(stext);
    }


void Client::ui_send_message(Channel& chan) {
	std::string recv_name;
	if(!load_recv(recv_name)) {
	    /*chacked for the first time - handle with it*/
	}
	send_message(recv_name, load_text_message(), chan);
    }



std::pair<std::string, std::vector<uint8_t>> Client::decrypt_msg(msg::Recv& msg_recv) {
        std::string sender_name = msg_recv.get_sender();
        auto it = contacts.find(sender_name);
        if (it == contacts.end()) {
            /* Some error or resolution of it */

        }
        std::vector<uint8_t> text_dec = cry::decrypt_aes(msg_recv.get_text(),{},it->second);
        return std::make_pair(sender_name,text_dec);
    }


std::pair<std::string,std::string> Client::handle_recv_msg(std::vector<uint8_t> msg_u) {
        std::unique_ptr<msg::Message> msg_des = msg::Recv::deserialize(msg_u);
        msg::Recv& recv_des = dynamic_cast<msg::Recv&>(*msg_des.get());
        auto sender_text = decrypt_msg(recv_des);
        std::string text_s(reinterpret_cast<char*> (sender_text.second.data()),sender_text.second.size());
        return std::make_pair(sender_text.first,text_s);
    }


void Client::ui_recv_message(std::vector<uint8_t> msg) {
       auto msg_param = handle_recv_msg(msg);
       std::cout << "Message from: "<< msg_param.first << std::endl;
       std::cout << "Text: " << msg_param.second << std::endl;
    }


bool Client::add_contact(std::string name, std::array<uint8_t,32> key) {
        auto it = contacts.find(name);
        if (it != contacts.end())
            return false;
        contacts[name]=key;
        return true;
    }


std::array<uint8_t,32> Client::get_key(std::string name) {
        return contacts[name];
    }


std::vector<uint8_t> Client::load_key(){
	std::string fname = pseudonym + ".key";
	return util::read_file(fname);
    }



void Client::write_key(std::vector<uint8_t>& key){
	std::string fname = pseudonym + ".key"; 	
	util::write_file(fname,key,false);
    }



void Client::run() {
        using asio::ip::tcp;
        asio::io_service io_service;

        tcp::socket sock{io_service};
        tcp::resolver resolver{io_service};
        asio::connect(sock, resolver.resolve({"127.0.0.1", "1337"}));

        Channel chan{std::move(sock)};
        initiate_connection(chan);
        for(;;) {
            send_message(pseudonym, "Ahoj, testuju zpravy v nejlepsim IM!", chan);
            auto [p, t] = handle_recv_msg(chan.recv());
            std::cout << p << ": " << t << std::endl;
        }
    }



void Client::initiate_connection(Channel& chan){ 
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

    chan.set_crybox(std::unique_ptr<CryBox>{new AESBox{K}});
    std::cout << "I am in!" << std::endl;
}

#endif
