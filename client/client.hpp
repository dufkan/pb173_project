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
#include "../shared/crybox.hpp"

#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;

using B32 = std::array<uint8_t, 32>;

class Client {
#ifdef TESTMODE
public:
#endif
    std::map<std::string, cry::AESKey> contacts;     /*Saved contacts with keys, old verion, for tests only*/
    std::map<std::string, DRBox> friend_box;    /*Saved sontacts with DrBoxes*/
    std::string pseudonym;      /*Pseudonym*/
    std::optional<Channel> chan;
    cry::ECKey IKey;        /*Identity Key*/
    cry::ECKey SPKey;       /*Signed Prekey*/
    cry::RSAKey signing_key; /*Signing key*/
    std::mutex output_mutex;
    std::istream& in;
    std::ostream& out;
    std::ostream& err;

    std::array<uint8_t, 512> SPK_sign;

    std::map<uint16_t, cry::ECKey> prekeys;     /*One time Prekeys*/


    msg::MessageDeserializer message_deserializer;

    /**
     * Adds a client to contacts, name of client is from in
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
     * ui, print them on out
     */
    void ret_online_message(std::vector<uint8_t> data);
     
    
    /**
     * Create disconnect message
     */
    std::vector<uint8_t> get_logout_message(); 

     /**
     * Create message Send from params and encrypt the text with AES-256 recv_key
     *
     * @param recv_name Pseudonym of reciever of the message
     * @param recv_key Symetric key for AES shared with reciever of the message
     * @param text Text of the message
     *
     * @return message Send
     */
    msg::Send create_message(std::string recv_name, cry::AESKey recv_key, std::vector<uint8_t> text);


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
    void ui_recv_message(const std::vector<uint8_t>& msg);

    /**
     * Thread for receiving messages
     */
    void recv_thread();

    /**
     * Generate a new one time prekey OPKey
     *
     * @return ID of the new prekey
     */
    uint16_t generate_prekey();


    /**
     * Generate long term prekeys IKey and/or SPKey
     *
     * @param which 's' - SPKey, 'i' - IKey, 'b' - both
     */
    void generate_prekey_lt(char which);


    /**
     * Compute shared key - the client who initiate connection
     * 
     * @param EK Ephermal key
     * @param oSPK Public part of (net yet) Signed prekey of second client
     * @param oIK Public part of Identity key of second client
     * @param oOPK Public part of One time prekey of second client or {}
     * 
     * @return shared key
     */
    cry::AESKey compute_share_init(cry::ECKey& EK, B32& oSPK, B32& oIK, B32 oOPK);

    
    /**
     * Compute shared key - the recv client of connection
     *
     * @param IK Public part of Identity key of the first client
     * @param EK Public part of Ephermal key of the first client
     * @param idOPK Id of One time prekey used by the fisrt client
     */
    cry::AESKey compute_share_recv(B32& IK, B32& EK, size_t idOPK); 

    /**
     * Save keys in files and be able to use them for next run
     * Use before exit
     *
     */
    void save_keys(); 


    /**
     * Load keys from files
     *
     */
    void load_keys(); 


    /**
     * Save contacts with keys for the next use
     *
     */
    void save_contacts();
    
    
    /**
     * Load contacts
     *
     */
    void load_contacts();

public:
    Client(std::string pseudonym = "noone", std::istream& in = std::cin, std::ostream& out = std::cout, std::ostream& err = std::cerr)
        : pseudonym(std::move(pseudonym)), in(in), out(out), err(err) {
        //generate_prekey();
        //generate_prekey_lt('s');
    }

    /**
     * Save psuedonym and key to cantacts
     *
     * @param name Pseudonym
     * @param key Key
     * @return true is everything is OK, false is the contact is already saved
     */
    bool add_contact(std::string name, cry::AESKey key);


    /**
     * Get key for pseudonym from saved contacts
     *
     * @param name Pseudonym
     * @return key
     */
    cry::AESKey get_key(std::string name);



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
        out << "a - add contact with defaul key K" << std::endl;
        out << "c - show saved contacts" << std::endl;
        out << "d - send me a dafualt message" << std::endl;
        out << "o - get online users" << std::endl;
        out << "q - disconnect" << std::endl;
        out << "s - send to another user a message" << std::endl;
        //out << "w - wait for a message" << std::endl;
        out << "x - add contact (ask for prekeys, compute share with X3DH" << std::endl;
        out << "z - send a message to (a user) me" << std::endl;
    }


    /**
     * From params create a X3DH initial message and serialize it and compute share secret
     *
     * @param pseudonym Pseudonym of recv
     * @param msg_prekey RetPrekey Message from server with prekeys
     * @param text Text in the initial message
     * @return serialized message
     */
    std::vector<uint8_t> x3dh_msg_byte(msg::RetPrekey& msg_prekey, std::string text); 

    /**
     * Handling with vector of byte X3dhInit message and compute share secret
     *
     * @param vestor of byte of the message
     * @return pair <name, text od init message>
     */
    std::pair<std::string, std::string> handle_x3dh_msg(std::vector<uint8_t> msg_u);
    


    /**
     * Create AskPrekey message with param pseudonym
     *  
     * @param pseudonym Client from who we want to have prekeys
     * @return serialized message
     */
    std::vector<uint8_t> ask_prekey_byte(std::string pseudonym) {
        msg::AskPrekey m{pseudonym};
        return m.serialize();
    }


    /**
     * Create new prekey and UploadPrekey message with it
     *
     * @return serialized message
     */
    std::vector<uint8_t> upload_prekey_byte(){
        uint16_t pid = generate_prekey();
        msg::UploadPrekey m{pid, prekeys[pid].get_bin_q()};
        return m.serialize();        
    }


    /**
     * Send some uploading message to server
     *
     */
    void upload_prekeys() {
        for (unsigned int i = prekeys.size(); i <= 10; i ++){
            chan->send(upload_prekey_byte());
        }
    }


    /**
     * Print saved contacts to std::cout
     *
     */ 
    void show_contacts() {
        #ifdef TESTMODE
        std::cout << "Contacts saved with keys: " << std::endl;
        for (auto& c : contacts) {
            std::cout << c.first << std::endl;
        }
        std::cout<< "Contacts saved with DrBox: " <<std::endl;
        #endif

        for (auto& c : friend_box) {
            std::cout << c.first << std::endl;
        }
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
    out << "Online users (" << oni.size() <<"):" <<std::endl;
    for (const std::string& on : oni) {
        out << on << std::endl;
    } 
}


std::vector<uint8_t> Client::get_logout_message(){
    msg::Logout m;
    return m.serialize();
}


msg::Send Client::create_message(std::string recv_name, cry::AESKey recv_key, std::vector<uint8_t> text) {
    std::vector text_enc = cry::encrypt_aes(text, {}, recv_key);
    msg::Send msg_send(recv_name,text_enc);
    return msg_send;
}



std::vector<uint8_t> Client::send_msg_byte(std::string recv_name, std::string text) {
    std::vector<uint8_t> text_u(text.begin(), text.end());
    auto it_recv_box = friend_box.find(recv_name);
    std::vector<uint8_t> msg_send_ser;

    if (it_recv_box != friend_box.end()) {
        std::vector<uint8_t> text_enc = it_recv_box->second.encrypt(text_u);
        msg::Send msg_send(recv_name,text_enc);
        msg_send_ser = msg_send.serialize();
    }

#ifdef TESTMODE
    else {    
    auto it_recv = contacts.find(recv_name);
    if (it_recv == contacts.end()) {
        /* Send a message to server fot recv keys and prekeys.... */
	    /*Is this checking for the second time needed?
        This should be error, it is chacked here for the second time */
    }
    msg::Send msg_send = create_message(recv_name, it_recv->second, text_u);
    msg_send_ser = msg_send.serialize();
    }
#endif
    return  msg_send_ser;
}


bool Client::load_recv(std::string& recv_name) {
	out << "Pseudonym: ";
    std::getline(in,recv_name);
    if(recv_name.size() < 2)
	    std::getline(in,recv_name);
	auto it = contacts.find(recv_name);
	return (it!=contacts.end());    
}



std::string Client::load_text_message() {
	std::string stext;
	out << "Text of the message: ";
	std::getline(in,stext);
	return stext;
    }


std::pair<std::string, std::string> Client::ui_get_param_msg() {
	std::string recv_name;
	if(!load_recv(recv_name)) {
	    /* Load pseudonym of receiver which is not saved in conntacts
           Does the user want to load the key and save it? */
	}
	return std::make_pair(recv_name, load_text_message());
}



std::pair<std::string, std::vector<uint8_t>> Client::decrypt_msg(msg::Recv& msg_recv) {
    std::string sender_name = msg_recv.get_sender();
    auto it_sender_box = friend_box.find(sender_name);
    std::vector<uint8_t> text_dec;
 
    if (it_sender_box != friend_box.end()) {
        text_dec = it_sender_box->second.decrypt(msg_recv.get_text());
        //std::cout <<
    }

#ifdef TESTMODE
    auto it_sender = contacts.find(sender_name);
    if (it_sender == contacts.end()) {
        /* Some error or resolution of it */

    }
    else if (it_sender_box == friend_box.end()) {
    text_dec = cry::decrypt_aes(msg_recv.get_text(),{},it_sender->second);
    }
#endif    
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


void Client::ui_recv_message(const std::vector<uint8_t>& msg) {
    auto msg_param = handle_recv_msg(msg);
    out << "Message from: "<< msg_param.first << std::endl;
    out << "Text: " << msg_param.second << std::endl;
}


bool Client::add_contact(std::string name, cry::AESKey key) {
    auto it = contacts.find(name);
    if (it != contacts.end())
        return false;
    contacts[name]=key;
    return true;
}


cry::AESKey Client::get_key(std::string name) {
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
         load_recv(name);
         cry::AESKey key = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
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

    upload_prekeys(); 

    std::vector<uint8_t> recv_byte;
    print_menu();
    auto t = std::thread(&Client::recv_thread, this);
    for(;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::lock_guard<std::mutex> lock{output_mutex};
        out << "> " << std::flush;
        char what;
        in >> what;
        std::string p, t;
        switch(what) {
            case 'a':
                add_friend();
                break;

            case 'c':
                show_contacts();
                break;
            
            case 'd':
                chan->send(send_msg_byte(pseudonym, "Ahoj, testuju zpravy"));
                break;

            case 'o':
                chan->send(get_online_message());
                break;
            
            case 's':
                std::tie(p, t) = ui_get_param_msg();
                chan->send(send_msg_byte(p, t));
                break;

            case 'x': {
                std::string recv;
                load_recv(recv);
                chan->send(ask_prekey_byte(recv));                
                break;}
            case 'z':
                std::tie(p, t) = ui_get_param_msg();
                chan->send(send_msg_byte(pseudonym, t));
                break;

        }
        if (what == 'q') {
            chan->send(get_logout_message());
            out << "Disconnecting..." << std::endl;
            break;
        }
    }
    t.join();
    save_contacts();
    save_keys();
}



void Client::initiate_connection(){
    std::vector<uint8_t> file_key = util::read_file("PUBSECRET");
    cry::RSAKey spub;
    spub.import(file_key);

    B32 Rc;
    cry::random_data(Rc);

    cry::RSAKey ckey;
    
    try {
        std::vector<uint8_t> file_ckey = util::read_file(pseudonym+".rsa");
        ckey.import(file_ckey);    
    } catch (std::ios_base::failure& e) {
        cry::generate_rsa_keys(ckey, ckey);
        util::write_file(pseudonym+".rsa",ckey.export_all(),false);
    }

    load_keys();
    load_contacts();
   
    msg::ClientInit init{pseudonym, Rc, ckey.export_pub()};
    init.encrypt(spub);
    chan->send(init);

    auto uniq_sresp = message_deserializer(chan->recv());
    auto sresp = dynamic_cast<msg::ServerResp&>(*uniq_sresp.get());
    sresp.decrypt(ckey);
    if (!sresp.check_mac()){
        /*trouble with integrity*/
        err << "Problem with integrity, MAC of sresp" << std::endl;
        return; //TODO handle with excetion
    } 
    auto [Rs, verify_Rc] = sresp.get();

    if(verify_Rc != Rc) {
        err << "There is a BIG problem! 'Rc != Rc'" << std::endl;
        return; // TODO handle with exception
    }

    Encoder e;
    e.put(Rs);
    e.put(Rc);
    cry::AESKey K = cry::hash_sha(e.move());

    msg::ClientResp cresp{Rs, IKey.get_bin_q(), SPKey.get_bin_q(), SPK_sign, signing_key.export_pub()};
    cresp.encrypt(K);
    chan->send(cresp);

    chan->set_crybox(std::unique_ptr<CryBox>{new SeqBox{new AESBox{K}, new MACBox{K}}});
    out << "I am in!" << std::endl;
}

void Client::handle_message(const std::vector<uint8_t>& data) {
    msg::MessageType mt = msg::type(data);
    switch (mt) {
        case msg::MessageType::Recv:
            {
                std::lock_guard<std::mutex> lock{output_mutex};
                ui_recv_message(data);
                out << std::flush;
            }
            break;
        case msg::MessageType::RetOnline:
            {
                std::lock_guard<std::mutex> lock{output_mutex};
                ret_online_message(data);
                out << std::flush;
            }
            break;
        case msg::MessageType::RetPrekey:
            {
                std::lock_guard<std::mutex> lock{output_mutex};
                std::string m = "Hello I want to connect with you, " + pseudonym;
                std::unique_ptr<msg::Message> msg_des = msg::RetPrekey::deserialize(data);
                msg::RetPrekey& recv_des = dynamic_cast<msg::RetPrekey&>(*msg_des.get());
                chan->send(x3dh_msg_byte(recv_des,m));
                out << std::flush;
            }
            break;
        case msg::MessageType::X3dhInit:
            {
                std::lock_guard<std::mutex> lock{output_mutex};
                auto [p,m] = handle_x3dh_msg(data);
                std::cout << m << std::endl << p << " was added to contacts." << std::endl;
                out << std::flush;
            }
            break;
        default:
            break;
    }
}

void Client::recv_thread() {
    for(;;) {
        std::vector<uint8_t> msg;
        try{
            msg = chan->recv();
        } catch (ChannelException &e){
            err << "Stop recv thread" << std::endl;
            break;
        }
        handle_message(std::move(msg));
    }
    out << "Ending recv_thread" << std::endl;
}

uint16_t Client::generate_prekey() {
    uint16_t id;
    do {
        auto data = cry::get_random_data(sizeof(uint16_t));
        std::copy(data.begin(), data.end(), reinterpret_cast<uint8_t*>(&id));
    } while(prekeys.find(id) != prekeys.end() && id != 0);
    prekeys[id].gen_pub_key();
    return id;
}


void Client::generate_prekey_lt(char which) {
    if (which == 'i' || which == 'b') {
        IKey.gen_pub_key();
    }

    if (which == 's' || which == 'b') {
        SPKey.gen_pub_key();
    } 
} 


std::vector<uint8_t> Client::x3dh_msg_byte(msg::RetPrekey& msg_prekey, std::string text) {
    auto SPK = msg_prekey.get_SPK();
    auto IK = msg_prekey.get_IK();
    auto sign = msg_prekey.get_sign();
    auto rsak = msg_prekey.get_signing_key();

    cry::RSAKey rsa_key;
    rsa_key.import(rsak);
    
    if (!rsa_key.has_pub()) {
        std::cerr << "Signing RSA key doesn't have public part." <<std::endl;
        /*TODO some error*/
        return {0,0};
    }
    
    if (!cry::rsa_verify(rsa_key, SPK, sign)) {
        std::cerr << "Signature of SPK is not OK." << std::endl;
        /* TODO some error*/
        return {0,0};
    }
    std::vector<uint8_t> text_u(text.begin(), text.end());
    cry::ECKey EK;
    EK.gen_pub_key();
    cry::AESKey K = compute_share_init(EK, SPK, IK, msg_prekey.get_OPK());

    contacts[msg_prekey.get_name()] = K; //TODO error if client is already saved in contacts
    friend_box.insert(std::make_pair(msg_prekey.get_name(),DRBox{K,EK}));
    auto text_enc = cry::encrypt_aes(text_u, {}, K);

    msg::X3dhInit msg{msg_prekey.get_name(), IKey.get_bin_q(), EK.get_bin_q(), msg_prekey.get_id(), text_enc};
    return msg.serialize();
}


std::pair<std::string, std::string> Client::handle_x3dh_msg(std::vector<uint8_t> msg_u) {
    std::unique_ptr<msg::Message> msg_des = msg::X3dhInit::deserialize(msg_u);
    msg::X3dhInit& x3dh_des = dynamic_cast<msg::X3dhInit&>(*msg_des.get());
    auto IK = x3dh_des.get_IK();
    auto EK = x3dh_des.get_EK();
    auto K = compute_share_recv(IK, EK, x3dh_des.get_id());
    
    contacts[x3dh_des.get_name()]=K; //TODO error if client is already saved in contacts
    friend_box.insert(std::make_pair(x3dh_des.get_name(),DRBox{K,EK}));
    auto text_dec = cry::decrypt_aes(x3dh_des.get_text(), {}, K);
    std::string text_s(text_dec.begin(), text_dec.end());
    return std::make_pair(x3dh_des.get_name(), text_s);
}



cry::AESKey Client::compute_share_init(cry::ECKey& EK, B32& oSPK, B32& oIK, B32 oOPK) {
    IKey.load_bin_qp(oSPK);
    IKey.compute_shared();
    cry::AESKey dh1 = IKey.get_shared(); 

    EK.load_bin_qp(oIK);
    EK.compute_shared();
    cry::AESKey dh2 = EK.get_shared();

    EK.load_bin_qp(oSPK);
    EK.compute_shared();
    cry::AESKey dh3 = EK.get_shared();

    std::vector<uint8_t> dh_con;
    dh_con.insert(dh_con.end(), dh1.begin(), dh1.end());
    dh_con.insert(dh_con.end(), dh2.begin(), dh2.end());
    dh_con.insert(dh_con.end(), dh3.begin(), dh3.end());
        
    if (oOPK != B32{}) {
        EK.load_bin_qp(oOPK);
        EK.compute_shared();
        cry::AESKey dh4 = EK.get_shared();

        dh_con.insert(dh_con.end(), dh4.begin(), dh4.end());
    }
        
    return cry::hash_sha(dh_con);
}


cry::AESKey Client::compute_share_recv(B32& IK, B32& EK, size_t idOPK) {
    SPKey.load_bin_qp(IK);
    SPKey.compute_shared();
    cry::AESKey dh1 = SPKey.get_shared();
    
    IKey.load_bin_qp(EK);
    IKey.compute_shared();
    cry::AESKey dh2 = IKey.get_shared();

    SPKey.load_bin_qp(EK);
    SPKey.compute_shared();
    cry::AESKey dh3 = SPKey.get_shared();
      
    std::vector<uint8_t> dh_con;
    dh_con.insert(dh_con.end(), dh1.begin(), dh1.end());
    dh_con.insert(dh_con.end(), dh2.begin(), dh2.end());
    dh_con.insert(dh_con.end(), dh3.begin(), dh3.end());
        
    if (prekeys.find(idOPK) != prekeys.end()) {
        prekeys[idOPK].load_bin_qp(EK);
        prekeys[idOPK].compute_shared();
        cry::AESKey dh4 = prekeys[idOPK].get_shared();
        prekeys.erase(idOPK);
        dh_con.insert(dh_con.end(), dh4.begin(), dh4.end());          
    }
    return cry::hash_sha(dh_con);
}


void Client::save_keys() {
        if(!fs::is_directory(pseudonym))
            fs::create_directory(pseudonym);
        util::write_file(pseudonym+"/IKey",IKey.get_key_binary(),false);
        util::write_file(pseudonym+"/SPKey", SPKey.get_key_binary(),false);
        util::write_file(pseudonym+"/signing_key", signing_key.export_all(),false);        

        Encoder enc;
        uint16_t num_opk = prekeys.size();
        enc.put(num_opk);
        for (auto& opk : prekeys) {
            std::vector<uint8_t> key = opk.second.get_key_binary();
            uint32_t size = key.size();
            enc.put(opk.first);
            enc.put(size);
            enc.put(key);
        }
        util::write_file(pseudonym+"/OPKeys",enc.get(),false);
    }


void Client::load_keys() { 
    try {
        std::vector<uint8_t> data = util::read_file(pseudonym+"/IKey");
        IKey.load_key_binary(data);
    } catch (std::ios_base::failure& e) {
        IKey.gen_pub_key();
    }

    try {
        std::vector<uint8_t> data = util::read_file(pseudonym+"/SPKey");
        SPKey.load_key_binary(data);
    } catch (std::ios_base::failure& e) {    
        SPKey.gen_pub_key();
    }        

    try {
        std::vector<uint8_t> data = util::read_file(pseudonym+"/signing_key");
        signing_key.import(data);
    } catch (std::ios_base::failure& e) {
        cry::generate_rsa_keys(signing_key,signing_key);
        auto to_sign = SPKey.get_bin_q();
        SPK_sign = cry::rsa_sign(signing_key,to_sign);
    }
        
    try {
        Decoder dec{util::read_file(pseudonym+"/OPKeys")};
        uint16_t num_opk = dec.get_u16();
        for (uint16_t i = 0; i < num_opk; i++) {
            uint16_t id = dec.get_u16();
            uint32_t size = dec.get_u32();
            prekeys[id].gen_pub_key();
            std::vector<uint8_t> data = dec.get_vec(size);
            prekeys[id].load_key_binary(data);
        }
    } catch (std::ios_base::failure& e) {        
    }
}


void Client::save_contacts(){
    if(!fs::is_directory(pseudonym))
        fs::create_directory(pseudonym);
    Encoder enc;
    enc.put((uint16_t) friend_box.size());
    for (auto& c : friend_box) {
        enc.put((uint8_t) c.first.size());
        enc.put(c.first);
        std::vector<uint8_t> dr_ser = c.second.serialize();
        enc.put((uint16_t) dr_ser.size());
        enc.put(dr_ser); 
    }
    util::write_file(pseudonym+"/friend_box",enc.get(),false);
#ifdef TESTMODE
    Encoder enc2;
    enc2.put((uint16_t) contacts.size());
    for (auto& c: contacts ) {
        enc2.put((uint8_t) c.first.size());
        enc2.put(c.first);
        enc2.put(c.second);       
    }
    util::write_file(pseudonym+"/contacts",enc2.get(),false);        
#endif
}    


void Client::load_contacts(){
    try {
        Decoder dec{util::read_file(pseudonym+"/friend_box")};
        uint16_t size = dec.get_u16();
        for (uint16_t i = 0; i < size; i++) {
            uint8_t len = dec.get_u8();
            std::string s = dec.get_str((size_t) len);
            uint16_t size = dec.get_u16();
            friend_box.insert(std::make_pair(s,DRBox{dec.get_vec((size_t) size)}));
        }
    } catch (std::ios_base::failure& e) {
    }

#ifdef TESTMODE
    try {
        Decoder dec{util::read_file(pseudonym+"/contacts")};
        uint16_t size = dec.get_u16();
        for (uint16_t i = 0; i < size; i++) {
            uint8_t len = dec.get_u8();
            std::string s = dec.get_str((size_t) len);
            contacts[s] = dec.get_arr<32>();
        }
    } catch (std::ios_base::failure& e) {        
    }
#endif

    
}


#endif
