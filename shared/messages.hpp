#ifndef MESSAGES_HPP
#define MESSAGES_HPP

#include <memory>
#include <unordered_map>
#include <vector>
#include <string>
#include <set>
#include <functional>

#include "crypto.hpp"
#include "codec.hpp"

namespace msg {

enum class MessageType : uint8_t {
    ClientInit,
    ServerResp,
    ClientResp,
    Logout,
    Send,
    Recv,
    ReqPrekey,
    RetPrekey,
    AskPrekey,
    UploadPrekey,
    GetOnline,
    RetOnline,
    ReqAlive,
    RespAlive
};

/**
 * Get type from binary representation of message
 *
 * @param msg Binary representation of message
 */
inline MessageType type(const std::vector<uint8_t>& msg) {
    return static_cast<MessageType>(msg[0]);
}

/**
 * Message interface
 *
 * Uniform way of handling messages in CryMe protocol.
 * Teoretical concept. Not yet fully functional.
 */
class Message {
/*protected:
    std::array<uint8_t,32> mac;
*/
public:
    virtual ~Message() {}
    
   

};

class ClientInit : public Message {
#ifdef TESTMODE
public:
#endif
    std::string pseudonym;
    
    std::array<uint8_t, 32> Rc;
    std::vector<uint8_t> key;

    std::vector<uint8_t> eRc;
    std::vector<uint8_t> epayload;

    std::array<uint8_t,32> mac;    

    ClientInit(std::vector<uint8_t> eRc, std::vector<uint8_t> epayload, std::array<uint8_t,32> mac = {}):
        eRc(std::move(eRc)), epayload(std::move(epayload)), mac(mac) {}
     
public:
    ClientInit(std::string pseudonym, std::array<uint8_t, 32> Rc, std::vector<uint8_t> key, std::array<uint8_t,32> mac = {}):
        pseudonym(std::move(pseudonym)), Rc(std::move(Rc)), key(std::move(key)), mac(mac) {}

    void encrypt(cry::RSAKey& server_pub) {
        eRc = cry::encrypt_rsa(Rc, server_pub);

        Encoder e;
        e.put(static_cast<uint16_t>(pseudonym.size()));
        e.put(pseudonym);
        e.put(static_cast<uint16_t>(key.size()));
        e.put(key);

        epayload = cry::encrypt_aes(e.move(), {}, Rc);
    }

    void decrypt(cry::RSAKey& server_priv) {
        std::vector<uint8_t> dRc = cry::decrypt_rsa(eRc, server_priv);
        std::copy(dRc.data(), dRc.data() + 32, Rc.data());

        Decoder d{cry::decrypt_aes(epayload, {}, Rc)};
        auto plen = d.get_u16();
        pseudonym = d.get_str(plen);
        auto klen = d.get_u16();
        key = d.get_vec(klen);
    }

    std::vector<uint8_t> serialize() const {
        Encoder e;
        e.put(static_cast<uint8_t>(MessageType::ClientInit));
        e.put(cry::mac_data(epayload,Rc));
        e.put(eRc);
        e.put(epayload);
        return e.move();
    }

    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data) {
        Decoder msg{data};
        msg.get_u8();

        //std::vector<uint8_t> mmac =  msg.get_vec(32);
        //std::copy(mmac.data(), mmac.data() + 32, mac.data());
        std::array<uint8_t,32> mmac = msg.get_arr<32>();
        std::vector<uint8_t> eRc = msg.get_vec(512);
        std::vector<uint8_t> epayload = msg.get_vec();
        
        return std::unique_ptr<ClientInit>(new ClientInit{eRc, epayload, mmac});
    }

    std::tuple<std::array<uint8_t, 32>, std::string, std::vector<uint8_t>> get() const {
        return {Rc, pseudonym, key};
    }

    friend bool operator==(const ClientInit& lhs, const ClientInit& rhs) {
        return lhs.pseudonym == rhs.pseudonym && lhs.Rc == rhs.Rc && lhs.key == rhs.key;
    }

    bool check_mac(){
        return cry::check_mac(epayload,Rc,mac);
    }
};

class ServerResp : public Message {
#ifdef TESTMODE
public:
#endif
    std::array<uint8_t, 32> Rs;
    std::array<uint8_t, 32> Rc;

    std::vector<uint8_t> eRs;
    std::vector<uint8_t> eRc;

    std::array<uint8_t,32> mac;

      
    ServerResp(std::vector<uint8_t> eRs, std::vector<uint8_t> eRc, std::array<uint8_t,32> mac = {}):
        eRs(std::move(eRs)), eRc(std::move(eRc)), mac(mac) {}
    

public:
    ServerResp(std::array<uint8_t, 32> Rs, std::array<uint8_t, 32> Rc, std::array<uint8_t,32> mac={}):
        Rs(std::move(Rs)), Rc(std::move(Rc)), mac(mac) {}

    
    void encrypt(cry::RSAKey& client_pub) {
        eRs = cry::encrypt_rsa(Rs, client_pub);
        eRc = cry::encrypt_aes(Rc, {}, Rs);
    }

    void decrypt(cry::RSAKey& client_priv) {
        std::vector<uint8_t> dRs = cry::decrypt_rsa(eRs, client_priv);
        std::copy(dRs.data(), dRs.data() + 32, Rs.data());

        std::vector<uint8_t> dRc = cry::decrypt_aes(eRc, {}, Rs);
        std::copy(dRc.data(), dRc.data() + 32, Rc.data());
    }

    std::vector<uint8_t> serialize() const {
        Encoder e;
        e.put(static_cast<uint8_t>(MessageType::ServerResp));
        e.put(cry::mac_data(eRc,Rs));
        e.put(eRs);
        e.put(eRc);
        return e.move();
    }

    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data) {
        Decoder msg{data};
        msg.get_u8();
        //std::vector<uint8_t> mmac = msg.get_vec(32);
        //std::copy(mmac.data(), mmac.data() + 32, mac.data());
        std::array<uint8_t,32> mmac = msg.get_arr<32>();
        auto eRs = msg.get_vec(512);
        auto eRc = msg.get_vec();

        return std::unique_ptr<ServerResp>(new ServerResp{eRs, eRc, mmac});
    }

    std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 32>> get() const {
        return {Rs, Rc};
    }

    friend bool operator==(const ServerResp& lhs, const ServerResp& rhs) {
        return lhs.Rs == rhs.Rs && lhs.Rc == rhs.Rc;
    }

    bool check_mac() {
        return cry::check_mac(eRc,Rs,mac);
    }
};

class ClientResp : public Message {
#ifdef TESTMODE
public:
#endif
    std::array<uint8_t, 32> Rs;
    std::vector<uint8_t> eRs;


    ClientResp(std::vector<uint8_t> eRs): eRs(std::move(eRs)) {}
public:
    ClientResp(std::array<uint8_t, 32> Rs): Rs(std::move(Rs)) {}

    void encrypt(const std::array<uint8_t, 32>& K) {
        eRs = cry::encrypt_aes(Rs, {}, K);
    }

    void decrypt(const std::array<uint8_t, 32>& K) {
        auto dRs = cry::decrypt_aes(eRs, {}, K);
        std::copy(dRs.data(), dRs.data() + 32, Rs.data());
    }

    std::vector<uint8_t> serialize() const {
        Encoder e;
        e.put(static_cast<uint8_t>(MessageType::ClientResp));
        e.put(eRs);
        return e.move();
    }

    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data) {
        Decoder msg{data};
        msg.get_u8();
        auto eRs = msg.get_vec();

        return std::unique_ptr<ClientResp>(new ClientResp{eRs});
    }

    std::array<uint8_t, 32> get() const {
        return Rs;
    }

    friend bool operator==(const ClientResp& lhs, const ClientResp& rhs) {
        return lhs.Rs == rhs.Rs;
    }

};

/**
 * Send message - to another user
 *
 */
class Send : public Message {
#ifdef TESTMODE
public:
#endif
    std::string receiver;
    std::vector<uint8_t> text;

public:
    /**
     * Create new instance of Send message
     *
     * @param name Pseudonym of the reciever of the message
     * @param ckey Symetric key shared with reciever of the message
     * @param skey Symetric key shared with the server
     * @param text Text of message sending to reciever
     */
    Send(std::string receiver, std::vector<uint8_t> text): receiver(receiver), text(text) {}


    /**
     * Deserialize Send message from its binary representation
     *
     * @param data Binary representation od Send message (without the first byte AKA type byte)
     *
     * @return Unique pointer to the deserialized
     */
    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data) {
        Decoder message{data};
        message.get_u8();
        uint8_t namelen = message.get_u8();
        std::string name = message.get_str(namelen);
        uint16_t textlen = message.get_u16();
        std::vector<uint8_t> text = message.get_vec(textlen);
        return std::make_unique<Send>(name, text);
    }


    /** 
     * Serialize message
     *
     * @return vector of bytes
     */
    std::vector<uint8_t> serialize() const {
        Encoder message;
        message.reserve(text.size() + receiver.size() + 1 + 2 + 1);
        message.put(static_cast<uint8_t>(MessageType::Send));
        message.put(static_cast<uint8_t>(receiver.size()));
        message.put(receiver);
        message.put(static_cast<uint16_t>(text.size()));
        message.put(text);
        return message.move();
    }

    std::string get_receiver() const {
        return receiver;
    }

    const std::vector<uint8_t>& get_text() const {
        return text;
    }

    bool operator==(const Send& s) const {
        return receiver == s.receiver && text == s.text;
    }
};

/**
 * Recieve message - from another user
 */
class Recv : public Message {
#ifdef TESTMODE
public:
#endif
    std::string sender;
    std::vector<uint8_t> text;

public:
    /**
     * Create new instance of Recieve message
     *
     * @param sender Pseudonym of the sender of the message
     * @param text Text of message
     */
    Recv(std::string sender, std::vector<uint8_t> text): sender(sender), text(text) {}

    /**
     * Deserialize Recieve message from its binary representation
     *
     * @param data Binary representation of Receive message (without the first byte AKA type byte)
     * @return Unique pointer to the object
     */
    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data) {
        Decoder message{data};
        message.get_u8();
        uint8_t namelen = message.get_u8();
        std::string name = message.get_str(namelen);
        uint16_t textlen = message.get_u16();
        std::vector<uint8_t> text = message.get_vec(textlen);
        return std::make_unique<Recv>(name, text);
    }

    /**
     * Serialize message
     *
     * @return vector of bytes
     */
    std::vector<uint8_t> serialize() const {
        Encoder message;
        message.reserve(text.size() + sender.size() + 1 + 2 + 1);
        message.put(static_cast<uint8_t>(MessageType::Recv));
        message.put(static_cast<uint8_t>(sender.size()));
        message.put(sender);
        message.put(static_cast<uint16_t>(text.size()));
        message.put(text);
        return message.move();
    }

    std::string get_sender() const {
        return sender;
    }

    const std::vector<uint8_t>& get_text() const {
        return text;
    }

    bool operator==(const Recv& s) const {
        return sender == s.sender && text == s.text;
    }
};
class Login : public Message {};
class Logout : public Message {};
class ReqPrekey : public Message {};
class RetPrekey : public Message {};
class AskPrekey : public Message {};
class UploadPrekey : public Message {};


/**
 * Get online message - from user to server
 */
class GetOnline : public Message{
public:

    std::vector<uint8_t> serialize() const {
        Encoder message;
        message.put(static_cast<uint8_t>(MessageType::GetOnline));
        return message.move();    
    }

    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data) {
        //Decoder message{data};
        return std::make_unique<GetOnline>();
    }
};


/**
 * Return online users - from server to user
 */
class RetOnline : public Message{
#ifdef TESTMODE
public:
#endif
    std::set<std::string> on_users;
public:
    
    RetOnline(std::set<std::string> on_users) : on_users(on_users) {}

    std::vector<uint8_t> serialize() {
        Encoder message;
        message.put(static_cast<uint8_t>(MessageType::RetOnline));
        message.put(static_cast<uint16_t>(on_users.size()));
        for (const std::string& onus : on_users) {
            message.put(static_cast<uint8_t>(onus.size()));
            message.put(onus);
        }
        return message.move();
    }


    std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data){
        Decoder message{data};
        message.get_u8();
        std::set<std::string> online;
        int onsize = static_cast<int>(message.get_u16());
        for (int i = 0; i < onsize; i++) {
            uint8_t namelen = message.get_u8();
            online.insert(message.get_str(namelen));
        }
        return std::make_unique<RetOnline>(online);
    }


    std::set<std::string> get_users() {
        return on_users;
    }


    bool is_online(const std::string& name) const {
        auto it = on_users.find(name);
        return (it != on_users.end());
    }    


    bool operator==(const RetOnline& ret) const {
        return (on_users == ret.on_users);
    }    
 };


class ReqAlive : public Message{
#ifdef TESTMODE
public:
#endif
    std::vector<uint8_t> value;

public:
    ReqAlive() : value(cry::get_random_data(32)) {}

    std::vector<uint8_t> serialize() {
        Encoder message;
        message.put(static_cast<uint8_t>(MessageType::ReqAlive));
        message.put(value);
        return message.move();
    }
    

    std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data){
        /*Decoder message{data};
        message.get_u8(); */
        return std::make_unique<ReqAlive>();
    }
};


class RespAlive : public Message{
#ifdef TESTMODE
public:
#endif
public:
    std::vector<uint8_t> serialize() {
        Encoder message;
        message.put(static_cast<uint8_t>(MessageType::RespAlive));
        return message.move();
    }

    std::unique_ptr<Message> deserialaze(const std::vector<uint8_t>& data){
        return std::make_unique<RespAlive>();
    }

};


/**
 * Deserializer for recreating messages transfered through network
 */
class MessageDeserializer {
    std::unordered_map<MessageType, std::function<std::unique_ptr<Message>(const std::vector<uint8_t>&)>> deserialize_map;

public:
    MessageDeserializer() {
        // create mapping between message types and deserialize function pointer
        deserialize_map.insert({MessageType::ClientInit, &ClientInit::deserialize});
        deserialize_map.insert({MessageType::ServerResp, &ServerResp::deserialize});
        deserialize_map.insert({MessageType::ClientResp, &ClientResp::deserialize});
        deserialize_map.insert({MessageType::Send, &Send::deserialize});
        deserialize_map.insert({MessageType::Recv, &Recv::deserialize});
    }

    /**
     * Deserialize message with respect to its real type
     *
     * @param msg Binary representation of the message
     *
     * @return Unique pointer to the deserialized Message
     */
    std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& msg) {
        return deserialize_map[type(msg)](msg);
    }

    std::unique_ptr<Message> operator()(const std::vector<uint8_t>& msg) {
        return deserialize(msg);
    }
};

} // namespace msg
#endif
