#ifndef CHANNEL_HPP
#define CHANNEL_HPP
#include "messages.hpp"
#include "asio.hpp"

class Channel {
    asio::io_service io_service;

public:
/*    Channel() {
        using asio::ip::tcp;

        tcp::resolver resolver{io_service};
        tcp::resolver::query query{"time-a-g.nist.gov", "daytime"};
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        tcp::socket socket{io_service};
        asio::connect(socket, endpoint_iterator);

        for(;;) {
            std::vector<char> buf;
            buf.resize(128);
            asio::error_code error;

            size_t len = socket.read_some(asio::buffer(buf), error);

            if (error == asio::error::eof)
                break; // Connection closed cleanly by peer.
            else if (error)
                throw asio::system_error(error); // Some other error

            std::cout.write(buf.data(), len);
        }
    }

    void send(const msg::Message& message) {
    }
*/
};

#endif
