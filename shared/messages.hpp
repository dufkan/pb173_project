#ifndef MESSAGES_HPP
#define MESSAGES_HPP

#include <memory>
#include <unordered_map>
#include <vector>
#include <string>
#include <functional>

#include "codec.hpp"

namespace msg {

enum class MessageType : uint8_t {
    Register,
    Login,
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
    /**
     * Serialize message into binary representation.
     */
    virtual std::vector<uint8_t> serialize() const { return {}; };

    virtual ~Message() {}
};

/**
 * Register message
 *
 * Message for new user registration.
 */
class Register : public Message {
    std::string name;
    std::vector<uint8_t> key;

public:
    /**
     * Create new instance of Register message.
     *
     * @param name Pseudonym of the user
     * @param key Public key of the user
     */
    Register(std::string name, std::vector<uint8_t> key): name(name), key(key) {}

    /**
     * Deserialize Register message from its binary representation
     *
     * @param data Binary representation of Register message (without the first byte AKA type byte)
     *
     * @return Unique pointer to the deserialized Message
     */
    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data) {
        Decoder message{data};
        message.get_u8();
        uint8_t namelen = message.get_u8();
        std::string name = message.get_str(namelen);
        uint16_t keylen = message.get_u16();
        std::vector<uint8_t> key = message.get_vec(keylen);
        return std::make_unique<Register>(name, key);
    }

    std::vector<uint8_t> serialize() const override {
        Encoder message;
        message.reserve(name.length() + key.size() + 2 + 1 + 1);
        message.put(static_cast<uint8_t>(MessageType::Register));
        message.put(static_cast<uint8_t>(name.size()));
        message.put(name);
        message.put(static_cast<uint16_t>(key.size()));
        message.put(key);
        return message.move();
    };

    /**
     * Get pseudonym from the message
     *
     * @return Pseudonym
     */
    std::string get_name() const {
        return name;
    }
    
    
    std::vector<uint8_t> get_key() const {
	return key;
    }


    bool operator== (const Register& a) const {
        return name == a.name && key == a.key;
    }
};


/**
 * Send message - to another user
 *
 */
class Send : public Message {
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


    std::vector<uint8_t> serialize() const override {
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


    std::vector<uint8_t> serialize() const override {
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
        deserialize_map.insert({MessageType::Register, &Register::deserialize});
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
