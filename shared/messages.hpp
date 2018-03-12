#ifndef MESSAGES_HPP
#define MESSAGES_HPP

#include <memory>
#include <unordered_map>
#include <vector>
#include <string>

namespace msg {

/**
 * Message interface
 *
 * Uniform way of handling messages in CryMe protocol.
 * Teoretical concept. Not yet fully functional.
 */
class Message {

    /**
     * Get type from binary representation of message
     *
     * @param msg Binary representation of message
     */
    static uint8_t type(const std::vector<uint8_t>& msg) {
        return msg[0];
    }

    /**
     * Get data from binary representation of message
     *
     * @param msg Binary representation of message
     */
    static std::vector<uint8_t> data(const std::vector<uint8_t>& msg) {
        return std::vector<uint8_t>{msg.begin() + 1, msg.end()}
    }

public:
    /**
     * Serialize message into binary representation.
     */
    virtual std::vector<uint8_t> serialize() const = 0;

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
     */
    static std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& data) {
        uint8_t name_len = data[0];
        std::string name{data.data() + 1, data[0]};
        return make_unique<Register>(name, {});
    }

    std::vector<uint8_t> serialize() const override {
        return {};
    };
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
 *
 * Much WIP, just look, do not touch!
 */
class MessageDeserializer {
    std::unordered_map<uint8_t, std::function<std::unique_ptr<Message>(const std::vector<uint8_t>&)>> deserialize_map;

public:
    MessageDeserializer() {
        // create mapping between message types and deserialize function pointer
        deserialize_map.insert({0x01, &Register::deserialize});
    }

    /**
     * Deserialize message with respect to its real type
     *
     * @param msg Binary representation of the message
     */
    std::unique_ptr<Message> deserialize(const std::vector<uint8_t>& msg) {
        return deserialize_map[Message::type(msg)](Message::data(msg));
    }
}

} // namespace msg
#endif
