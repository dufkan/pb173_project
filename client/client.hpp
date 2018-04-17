#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <vector>
#include <string>
#include <iostream>
#include <map>
#include <optional>
#include <thread>
#include <chrono>
#include <mutex>
#include <cstdio>

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
    std::optional<Channel> chan;
    std::mutex output_mutex;

    msg::MessageDeserializer message_deserializer;

    /**
     * Adds a client to contacts, name of client is from std::cin
     * Function for testing only, only one key for everyone
     */
    void add_friend();


    /**
     * Handle incomming message
     */
    void handle_message(const std::vector<uint8_t>& data);

    /**
     * Create message for getting online users
     *
     */
    std::vector<uint8_t> get_online_message();


    /**
     * Handle with message with online users
     * ui, print them on std::cout
     */
    void ret_online_message(std::vector<uint8_t> data);
    

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
     * Encrypt text, create msg Send from params and return it as a vector of bytes ready to send
     *   
     * @param recv_name Pseudonym of receiver
     * @param text text of the message
     * @return vector of bytes with the message
     */
    std::vector<uint8_t> send_msg_byte(std::string recv_name, std::string text);


    /**
     * Get from user receiver pseudonym
     *
     * @param recv_name Pseudonym of receiver
     * @return true if the pseudonym is saved in conntacts
     */
    bool load_recv(std::string& recv_name); 



    /**
     * Get from user text of the message and return it as a string
     *
     * @return the text
     */
    std::string load_text_message();


    /**
     * Gets from user params for sending message
     *
     * @return pair of receiver pseudonym and text of the message
     */
    std::pair<std::string, std::string> ui_get_param_msg(); 


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

    /**
     * Thread for receiving messages
     */
    void recv_thread();

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
    void initiate_connection();


    void print_menu() {
        using std::cout;
        cout << "a - add contact" << std::endl;
        cout << "o - get online users" << std::endl;
        cout << "z - send a message to (a user) me" << std::endl;
        cout << "d - send me a dafualt message" << std::endl;
        cout << "s - send to another user a message" << std::endl;
        cout << "v - check is there is a message for me" << std::endl;
        cout << "w - wait for a message" << std::endl;
    }

}; //Client


std::vector<uint8_t> Client::get_online_message(){
    msg::GetOnline m;
    return m.serialize();
}


void Client::ret_online_message(std::vector<uint8_t> data) {
    std::unique_ptr<msg::Message> des = msg::RetOnline::deserialize(data);
    msg::RetOnline& msg_on = dynamic_cast<msg::RetOnline&>(*des.get());

    std::set<std::string> oni = msg_on.get_users();
    std::cout << "Online users (" << oni.size() <<"):" <<std::endl;
    for (const std::string& on : oni) {
        std::cout << on << std::endl;
    } 
}



msg::Send Client::create_message(std::string recv_name, std::array<uint8_t, 32> recv_key, std::vector<uint8_t> text) {
    std::vector text_enc = cry::encrypt_aes(text, {}, recv_key);
    msg::Send msg_send(recv_name,text_enc);
    return msg_send;
}



std::vector<uint8_t> Client::send_msg_byte(std::string recv_name, std::string text) {
    std::vector<uint8_t> text_u(text.begin(), text.end());
    auto it_recv = contacts.find(recv_name);
    
    if (it_recv == contacts.end()) {
        /* Send a message to server fot recv keys and prekeys.... */
	    /*Is this checking for the second time needed?
        This should be error, it is chacked here for the second time */
    }
    
    msg::Send msg_send = create_message(recv_name, it_recv->second, text_u);
    return  msg_send.serialize();
}


bool Client::load_recv(std::string& recv_name) {
	std::cout << "Pseudonym: ";
    std::getline(std::cin,recv_name);
    if(recv_name.size() < 2)
	    std::getline(std::cin,recv_name);
	auto it = contacts.find(recv_name);
	return (it!=contacts.end());    
}



std::string Client::load_text_message() {
	std::string stext;
	std::cout << "Text of the message: ";
	std::getline(std::cin,stext);
	return stext;
    }


std::pair<std::string, std::string> Client::ui_get_param_msg() {
	std::string recv_name;
	if(!load_recv(recv_name)) {
	    /* Load pseudonym of receiver which is not saved in conntacts
           Does the user want to load the key and save it? */
	}
	//std::cout << "Get: "<<recv_name <<std::endl;
	return std::make_pair(recv_name, load_text_message());
}



std::pair<std::string, std::vector<uint8_t>> Client::decrypt_msg(msg::Recv& msg_recv) {
    std::string sender_name = msg_recv.get_sender();
    auto it_sender = contacts.find(sender_name);
    if (it_sender == contacts.end()) {
        /* Some error or resolution of it */

    }
    std::vector<uint8_t> text_dec = cry::decrypt_aes(msg_recv.get_text(),{},it_sender->second);
    return std::make_pair(sender_name,text_dec);
}


std::pair<std::string,std::string> Client::handle_recv_msg(std::vector<uint8_t> msg_u) {
    std::unique_ptr<msg::Message> msg_des = msg::Recv::deserialize(msg_u);
    msg::Recv& recv_des = dynamic_cast<msg::Recv&>(*msg_des.get());
    
    auto it = contacts.find(recv_des.get_sender());
    if (it == contacts.end()) {
        /* Some error or resolution of it */

    } 
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


void Client::add_friend() {
         std::string name;
         bool okaa = load_recv(name);
         std::array<uint8_t, 32> key = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
        /*std::string fname = "friend_" + name; 
        try {
            std::vector<uint8_t> file_ckey = util::read_file(fname);
            copy(file_ckey.begin(),file_ckey.begin()+32,key.begin());
    
        } catch (std::ios_base::failure& e) {
            cry::generate_rsa_keys(ckey, ckey);
            util::write_file(pseudonym,ckey.export_all(),false);
        }*/

        add_contact(name,key);     
    }




void Client::run() {
    using asio::ip::tcp;
    asio::io_service io_service;

    tcp::socket sock{io_service};
    tcp::resolver resolver{io_service};
    asio::connect(sock, resolver.resolve({"127.0.0.1", "1337"}));

    chan = Channel{std::move(sock)};
    initiate_connection();

    std::vector<uint8_t> recv_byte;
    print_menu();
    auto t = std::thread(&Client::recv_thread, this);
    for(;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::lock_guard<std::mutex> lock{output_mutex};
        std::cout << "> " << std::flush;
        char what;
        std::cin >> what;
        std::string p, t;
        switch(what) {
            case 'a':
                add_friend();
                break;
            case 'o':
                chan->send(get_online_message());
                break;
            case 'd':
                chan->send(send_msg_byte(pseudonym, "Ahoj, testuju zpravy"));
                break;
            case 'z':
                std::tie(p, t) = ui_get_param_msg();
                chan->send(send_msg_byte(pseudonym, t));
                break;
            case 's':
                std::tie(p, t) = ui_get_param_msg();
                chan->send(send_msg_byte(p, t));
                break;
        }
    }
    t.join();
}



void Client::initiate_connection(){
    std::vector<uint8_t> file_key = util::read_file("PUBSECRET");
    cry::RSAKey spub;
    spub.import(file_key);

    std::array<uint8_t, 32> Rc;
    cry::random_data(Rc);

    cry::RSAKey ckey;
    
    try {
        std::vector<uint8_t> file_ckey = util::read_file(pseudonym);
        ckey.import(file_ckey);    
    } catch (std::ios_base::failure& e) {
        cry::generate_rsa_keys(ckey, ckey);
        util::write_file(pseudonym,ckey.export_all(),false);
    }
   
    msg::ClientInit init{pseudonym, Rc, ckey.export_pub()};
    init.encrypt(spub);
    chan->send(init);

    auto uniq_sresp = message_deserializer(chan->recv());
    auto sresp = dynamic_cast<msg::ServerResp&>(*uniq_sresp.get());
    sresp.decrypt(ckey);
    if (!sresp.check_mac()){
        /*trouble with integrity*/
        std::cerr << "Problem with integrity, MAC of sresp" << std::endl;
        return; //TODO handle with excetion
    }
    auto [Rs, verify_Rc] = sresp.get();

    if(verify_Rc != Rc) {
        std::cerr << "There is a BIG problem! 'Rc != Rc'" << std::endl;
        return; // TODO handle with exception
    }

    Encoder e;
    e.put(Rs);
    e.put(Rc);
    std::array<uint8_t, 32> K = cry::hash_sha(e.move());

    msg::ClientResp cresp{Rs};
    cresp.encrypt(K);
    chan->send(cresp);

    chan->set_crybox(std::unique_ptr<CryBox>{new SeqBox{new AESBox{K}, new MACBox{K}}});
    std::cout << "I am in!" << std::endl;
}

void Client::handle_message(const std::vector<uint8_t>& data) {
    msg::MessageType mt = msg::type(data);
    switch (mt) {
        case msg::MessageType::Recv:
            {
                std::lock_guard<std::mutex> lock{output_mutex};
                ui_recv_message(data);
                std::cout << std::flush;
            }
            break;
        case msg::MessageType::RetOnline:
            {
                std::lock_guard<std::mutex> lock{output_mutex};
                ret_online_message(data);
                std::cout << std::flush;
            }
            break;
    }
}

void Client::recv_thread() {
    for(;;) {
        std::vector<uint8_t> msg = chan->recv();
        handle_message(std::move(msg));
    }
}
#endif
