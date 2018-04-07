#ifndef MESSAGES_HPP
#define MESSAGES_HPP

#include <memory>
#include <unordered_map>
#include <vector>
#include <string>
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

    ClientInit(std::vector<uint8_t> eRc, std::vector<uint8_t> epayload):
        eRc(std::move(eRc)), epayload(std::move(epayload)) {}

public:
    ClientInit(std::string pseudonym, std::array<uint8_t, 32> Rc, std::vector<uint8_t> key):
        pseudonym(std::move(pseudonym)), Rc(std::move(Rc)), key(std::move(key)) {}

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
        e.put(eRc);
        e.put(epayload);
        return e.move();
    }

    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data) {
        Decoder msg{data};
        msg.get_u8();

        std::vector<uint8_t> eRc = msg.get_vec(512);
        std::vector<uint8_t> epayload = msg.get_vec();

        return std::unique_ptr<ClientInit>(new ClientInit{eRc, epayload});
    }

    std::tuple<std::array<uint8_t, 32>, std::string, std::vector<uint8_t>> get() const {
        return {Rc, pseudonym, key};
    }

    friend bool operator==(const ClientInit& lhs, const ClientInit& rhs) {
        return lhs.pseudonym == rhs.pseudonym && lhs.Rc == rhs.Rc && lhs.key == rhs.key;
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


    ServerResp(std::vector<uint8_t> eRs, std::vector<uint8_t> eRc):
        eRs(std::move(eRs)), eRc(std::move(eRc)) {}
public:
    ServerResp(std::array<uint8_t, 32> Rs, std::array<uint8_t, 32> Rc):
        Rs(std::move(Rs)), Rc(std::move(Rc)) {}

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
        e.put(eRs);
        e.put(eRc);
        return e.move();
    }

    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data) {
        Decoder msg{data};
        msg.get_u8();
        auto eRs = msg.get_vec(512);
        auto eRc = msg.get_vec();

        return std::unique_ptr<ServerResp>(new ServerResp{eRs, eRc});
    }

    std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 32>> get() const {
        return {Rs, Rc};
    }

    friend bool operator==(const ServerResp& lhs, const ServerResp& rhs) {
        return lhs.Rs == rhs.Rs && lhs.Rc == rhs.Rc;
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
};

} // namespace msg
#endif
