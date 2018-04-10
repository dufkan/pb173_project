#ifndef CHANNEL_HPP
#define CHANNEL_HPP
#include <type_traits>
#include <memory>

#include "asio.hpp"
#include "crypto.hpp"
#include "crybox.hpp"

class Channel {
#ifdef TESTMODE
public:
#endif
    asio::ip::tcp::socket sock;
    std::unique_ptr<CryBox> crybox;
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
    Channel(asio::ip::tcp::socket&& sock): sock(std::move(sock)), crybox(std::make_unique<IdBox>()) {}

    template<typename M, typename = typename std::enable_if<std::is_base_of<msg::Message, M>::value>>
    void send(const M& msg) {
        send(msg.serialize());
    }

    void send(const std::vector<uint8_t>& msg) {
        std::vector<uint8_t> emsg = crybox->encrypt(msg);

        Encoder e;
        e.put(static_cast<uint16_t>(emsg.size()));
        std::vector<uint8_t> header = e.move();

        asio::write(sock, asio::buffer(header));
        asio::write(sock, asio::buffer(emsg));
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

        return crybox->decrypt(msg);
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

    void set_crybox(std::unique_ptr<CryBox>&& cb) {
        crybox = std::move(cb);
    }
};

#endif
