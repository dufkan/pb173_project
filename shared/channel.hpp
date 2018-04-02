#ifndef CHANNEL_HPP
#define CHANNEL_HPP
#include "messages.hpp"
#include "asio.hpp"

class Channel {
    //asio::ip::tcp::socket sock;
    std::array<uint8_t, 32> key;

public:
    Channel() {}

    void send(const msg::Message& message) {
    }
};

#endif
