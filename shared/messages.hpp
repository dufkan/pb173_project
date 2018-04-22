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
    RespAlive,
    X3dhInit
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

    friend bool operator!=(const ClientInit& lhs, const ClientInit& rhs) {
        return !(lhs == rhs);
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

    friend bool operator!=(const ServerResp& lhs, const ServerResp& rhs) {
        return !(lhs == rhs);
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

    friend bool operator!=(const ClientResp& lhs, const ClientResp& rhs) {
        return !(lhs == rhs);
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

    friend bool operator==(const Send& lhs, const Send& rhs) {
        return lhs.receiver == rhs.receiver && lhs.text == rhs.text;
    }

    friend bool operator!=(const Send& lhs, const Send& rhs) {
        return !(lhs == rhs);
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

    friend bool operator==(const Recv& lhs, const Recv& rhs) {
        return lhs.sender == rhs.sender && lhs.text == rhs.text;
    }

    friend bool operator!=(const Recv& lhs, const Recv& rhs) {
        return !(lhs == rhs);
    }
};

class Login : public Message {};

/**
 * Message sent by server when requesting a new prekey.
 */
class ReqPrekey : public Message {
public:
    std::vector<uint8_t> serialize() const {
        Encoder message;
        message.put(static_cast<uint8_t>(MessageType::ReqPrekey));
        return message.move();
    }

    static std::unique_ptr<Message> deserialize([[maybe_unused]] const std::vector<uint8_t>& data) {
        return std::make_unique<ReqPrekey>();
    }

    friend bool operator==([[maybe_unused]] const ReqPrekey& lhs, [[maybe_unused]] const ReqPrekey& rhs) {
        return true;
    }

    friend bool operator!=(const ReqPrekey& lhs, const ReqPrekey& rhs) {
        return !(lhs == rhs);
    }
};

/**
 * Message sent by server when returning asked for key to certain user.
 */
class RetPrekey : public Message {
#ifdef TESTMODE
public:
#endif
    std::string pseudonym;
    uint16_t id;    /*one time prekey id*/
    std::array<uint8_t, 32> OPKey; /*one time prekey*/
    std::array<uint8_t, 32> IKey; /*identity key*/
    std::array<uint8_t, 32> SPKey; /*(not yet) signed prekey*/
public:
    RetPrekey(std::string pseudonym, uint16_t id, std::array<uint8_t, 32> OPKey, std::array<uint8_t, 32> IKey, std::array<uint8_t, 32> SPKey): pseudonym(std::move(pseudonym)), id(id), OPKey(std::move(OPKey)), IKey(std::move(IKey)), SPKey(std::move(SPKey)) {}

    std::vector<uint8_t> serialize() const {
        Encoder message;
        message.put(static_cast<uint8_t>(MessageType::RetPrekey));
        message.put(static_cast<uint8_t>(pseudonym.size()));
        message.put(pseudonym);
        message.put(static_cast<uint16_t>(id));
        message.put(OPKey);
        message.put(IKey);
        message.put(SPKey);
        return message.move();
    }

    static std::unique_ptr<Message> deserialize([[maybe_unused]] const std::vector<uint8_t>& data) {
        Decoder d{data};
        d.get_u8();
        uint8_t plen = d.get_u8();
        std::string pseudonym = d.get_str(plen);
        uint16_t id = d.get_u16();
        auto OPKey = d.get_arr<32>();
        auto IKey = d.get_arr<32>();
        auto SPKey = d.get_arr<32>();
        return std::make_unique<RetPrekey>(std::move(pseudonym), id, std::move(OPKey), std::move(IKey), std::move(SPKey));
    }

    friend bool operator==(const RetPrekey& lhs, const RetPrekey& rhs) {
        return lhs.pseudonym == rhs.pseudonym && lhs.id == rhs.id && lhs.OPKey == rhs.OPKey && lhs.IKey == rhs.IKey && lhs.SPKey == rhs.SPKey ;
    }

    friend bool operator!=(const RetPrekey& lhs, const RetPrekey& rhs) {
        return !(lhs == rhs);
    }

    std::string get_name() {
        return pseudonym;
    }

    uint16_t get_id() {
        return id;
    }

    std::array<uint8_t, 32> get_OPK() {
        return OPKey;
    }

    std::array<uint8_t, 32> get_IK() {
        return IKey;
    }

    std::array<uint8_t, 32> get_SPK() {
        return SPKey;
    }
};

/**
 * Message sent by client to request prekey of some other client (specified by pseudonym).
 */
class AskPrekey : public Message {
#ifdef TESTMODE
public:
#endif
    std::string pseudonym;
public:
    AskPrekey(std::string pseudonym): pseudonym(std::move(pseudonym)) {}

    std::vector<uint8_t> serialize() const {
        Encoder message;
        message.put(static_cast<uint8_t>(MessageType::AskPrekey));
        message.put(static_cast<uint8_t>(pseudonym.size()));
        message.put(pseudonym);
        return message.move();
    }

    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data) {
        Decoder d{data};
        d.get_u8();
        uint8_t plen = d.get_u8();
        std::string pseudonym = d.get_str(plen);
        return std::make_unique<AskPrekey>(std::move(pseudonym));
    }

    friend bool operator==(const AskPrekey& lhs, const AskPrekey& rhs) {
        return lhs.pseudonym == rhs.pseudonym;
    }

    friend bool operator!=(const AskPrekey& lhs, const AskPrekey& rhs) {
        return !(lhs == rhs);
    }
};

/**
 * Message sent by client to upload new prekey to server.
 */
class UploadPrekey : public Message {
#ifdef TESTMODE
public:
#endif
    uint16_t id;
    std::array<uint8_t, 32> key;
public:
    UploadPrekey(uint16_t id, std::array<uint8_t, 32> key): id(id), key(std::move(key)) {}

    std::vector<uint8_t> serialize() const {
        Encoder message;
        message.put(static_cast<uint8_t>(MessageType::UploadPrekey));
        message.put(static_cast<uint16_t>(id));
        message.put(key);
        return message.move();
    }

    static std::unique_ptr<Message> deserialize([[maybe_unused]] const std::vector<uint8_t>& data) {
        Decoder d{data};
        d.get_u8();
        uint16_t id = d.get_u16();
        auto key = d.get_arr<32>();
        return std::make_unique<UploadPrekey>(id, std::move(key));
    }

    friend bool operator==(const UploadPrekey& lhs, const UploadPrekey& rhs) {
        return lhs.id == rhs.id && lhs.key == rhs.key;
    }

    friend bool operator!=(const UploadPrekey& lhs, const UploadPrekey& rhs) {
        return !(lhs == rhs);
    }
};

/**
 * Logout user from connection - msg from user to server
 */
class Logout : public Message {
public:
    std::vector<uint8_t> serialize() const {
        Encoder message;
        message.put(static_cast<uint8_t>(MessageType::Logout));
        auto data = cry::get_random_data((size_t) 16);
        message.put(data);

        return message.move();
    }

    static std::unique_ptr<Message> deserialize([[maybe_unused]] const std::vector<uint8_t>& data) {
        return std::make_unique<Logout>();
    }
};


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

    static std::unique_ptr<Message> deserialize([[maybe_unused]] const std::vector<uint8_t>& data) {
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


    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data){
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

    friend bool operator==(const RetOnline& lhs, const RetOnline& rhs) {
        return lhs.on_users == rhs.on_users;
    }

    friend bool operator!=(const RetOnline& lhs, const RetOnline& rhs) {
        return !(lhs == rhs);
    }
 };


class ReqAlive : public Message {
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


    static std::unique_ptr<Message> deserialize([[maybe_unused]] const std::vector<uint8_t>& data){
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

    static std::unique_ptr<Message> deserialize([[maybe_unused]] const std::vector<uint8_t>& data){
        return std::make_unique<RespAlive>();
    }

};


class X3dhInit : public Message{
#ifdef TESTMODE
public:
#endif
    std::string pseudonym;
    std::array<uint8_t, 32> IK;
    std::array<uint8_t, 32> EK;
    uint16_t id;
    std::vector<uint8_t> text;

public:
    X3dhInit(std::string pseudonym, std::array<uint8_t, 32> IK, std::array<uint8_t, 32> EK, uint16_t id, std::vector<uint8_t> text) : pseudonym(pseudonym), IK(std::move(IK)), EK(std::move(EK)), id(id), text(std::move(text)) {}

    std::vector<uint8_t> serialize() {
        Encoder msg;
        msg.put(static_cast<uint8_t>(MessageType::X3dhInit));
        msg.put(static_cast<uint8_t>(pseudonym.size()));
        msg.put(pseudonym);
        msg.put(IK);
        msg.put(EK);
        msg.put(static_cast<uint16_t>(id));
        msg.put(static_cast<uint16_t>(text.size()));
        msg.put(text);
        return msg.move();
    }


    static std::unique_ptr<Message> deserialize([[maybe_unused]] const std::vector<uint8_t>& data){
        Decoder d{data};
        d.get_u8();
        uint8_t namelen = d.get_u8();
        std::string name = d.get_str(namelen);
        auto IK = d.get_arr<32>();
        auto EK = d.get_arr<32>();
        uint16_t id = d.get_u16();
        uint16_t textlen = d.get_u16();
        auto text = d.get_vec(textlen);
         
        return std::make_unique<X3dhInit>(name,std::move(IK),std::move(EK),id,std::move(text));
    }

    std::string get_name() {
        return pseudonym;
    }

    std::array<uint8_t, 32> get_IK(){
        return IK;
    }

    std::array<uint8_t, 32> get_EK(){
        return EK;
    }

    uint16_t get_id(){
        return id;
    }

    std::vector<uint8_t> get_text() {
        return text;
    }


    friend bool operator==(const X3dhInit& lhs, const X3dhInit& rhs) {
        return lhs.pseudonym == rhs.pseudonym && lhs.IK == rhs.IK && lhs.EK == rhs.EK && lhs.id == rhs.id && lhs.text == rhs.text;
    }

    friend bool operator!=(const X3dhInit& lhs, const X3dhInit& rhs) {
        return !(lhs == rhs);
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
        deserialize_map.insert({MessageType::GetOnline, &GetOnline::deserialize});
        deserialize_map.insert({MessageType::RetOnline, &RetOnline::deserialize});
        deserialize_map.insert({MessageType::ReqAlive, &ReqAlive::deserialize});
        deserialize_map.insert({MessageType::RespAlive, &RespAlive::deserialize});
        deserialize_map.insert({MessageType::Logout, &Logout::deserialize});
        deserialize_map.insert({MessageType::ReqPrekey, &ReqPrekey::deserialize});
        deserialize_map.insert({MessageType::RetPrekey, &RetPrekey::deserialize});
        deserialize_map.insert({MessageType::UploadPrekey, &UploadPrekey::deserialize});
        deserialize_map.insert({MessageType::AskPrekey, &AskPrekey::deserialize});
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
