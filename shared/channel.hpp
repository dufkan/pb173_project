#ifndef CHANNEL_HPP
#define CHANNEL_HPP
#include "messages.hpp"
#include "asio.hpp"

class Channel {
#ifdef TESTMODE
public:
#endif
    asio::ip::tcp::socket sock;
    std::array<uint8_t, 32> key;
    Decoder decoder;
    uint16_t msglen = 0;

    size_t recv_data() {
        uint8_t buffer[1024];
        size_t len = sock.read_some(asio::buffer(buffer, 1024));
        decoder.append(buffer, len);
        return len;
    }

    size_t try_recv_data() {
        return sock.available() > 0 ? recv_data() : 0;
    }

    void try_msglen() {
        if(msglen == 0 && decoder.size() >= 2)
            msglen = decoder.get_u16();
    }

public:
    Channel(asio::ip::tcp::socket&& sock): sock(std::move(sock)) {}

    void send(const std::vector<uint8_t> msg) {
        Encoder e;
        e.put(static_cast<uint16_t>(msg.size()));
        std::vector<uint8_t> header = e.move();
        asio::write(sock, asio::buffer(header));
        asio::write(sock, asio::buffer(msg));
    }

    std::vector<uint8_t> recv() {
        try_msglen();
        while(msglen == 0 || decoder.size() < msglen) {
            recv_data();
            try_msglen();
        }
        auto msg = decoder.get_vec(msglen);
        msglen = 0;
        decoder.cut();
        return msg;
    }

    std::vector<uint8_t> try_recv() {
        try_msglen();
        if(msglen == 0 && sock.available() >= 2) {
            recv_data();
            return try_recv();
        }
        if(msglen != 0 && decoder.size() + sock.available() >= msglen)
            return recv();
        return {};
    }
};

#endif
