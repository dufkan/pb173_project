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
    Challenge,
    Response,
    Send,
    Receive,
    ReqKey,
    RetKey,
};

/**
 * Get type from binary representation of message
 *
 * @param msg Binary representation of message
 */
inline MessageType type(const std::vector<uint8_t>& msg) {
    return static_cast<MessageType>(msg[2]);
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
        uint8_t msgtype = message.get_u8();
        uint8_t namelen = message.get_u8();
        std::string name = message.get_str(namelen);
        uint16_t keylen = message.get_u16();
        std::vector<uint8_t> key = message.get_vec(keylen);
        return std::make_unique<Register>(name, key);
    }

    std::vector<uint8_t> serialize() const override {
        Encoder message;
        message.reserve(name.length() + 1 + 1);
        message.put(static_cast<uint8_t>(MessageType::Register));
        message.put(static_cast<uint8_t>(name.size()));
        message.put(name);
        message.put(static_cast<uint16_t>(key.size()));
        message.put(key);
        return message.get();
    };

    /**
     * Get pseudonym from the message
     *
     * @return Pseudonym
     */
    std::string get_name() const {
        return name;
    }
};


class Challenge : public Message {};
class Response : public Message {};
class Send : public Message {};
class Receive : public Message {};
class Login : public Message {};
class Logout : public Message {};
class ReqKey : public Message {};
class RetKey : public Message {};

/**
 * Deserializer for recreating messages transfered through network
 */
class MessageDeserializer {
    std::unordered_map<MessageType, std::function<std::unique_ptr<Message>(const std::vector<uint8_t>&)>> deserialize_map;

public:
    MessageDeserializer() {
        // create mapping between message types and deserialize function pointer
        deserialize_map.insert({MessageType::Register, &Register::deserialize});
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
