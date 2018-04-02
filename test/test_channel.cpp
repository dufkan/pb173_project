#include "../shared/channel.hpp"
#include <thread>
#include <iostream>

TEST_CASE("Channel") {
    using asio::ip::tcp;

    asio::io_service sios;
    tcp::acceptor acc{sios, tcp::endpoint(tcp::v4(), 1337)};
    tcp::socket ssock{sios};
    std::thread sthread([&]{
        acc.accept(ssock);
    });

    asio::io_service cios;
    tcp::socket csock{cios};
    tcp::resolver resolver{cios};
    asio::connect(csock, resolver.resolve({"127.0.0.1", "1337"}));

    sthread.join();

    Channel schan{std::move(ssock)};
    Channel cchan{std::move(csock)};


    std::vector<uint8_t> msg{0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    for(int i = 0; i < 5; ++i)
        cchan.send(msg);

    for(int i = 0; i < 5; ++i)
        REQUIRE(schan.recv() == msg);
    REQUIRE(schan.try_recv() == std::vector<uint8_t>{});
}

TEST_CASE("Channel with encryption") {
    using asio::ip::tcp;

    asio::io_service sios;
    tcp::acceptor acc{sios, tcp::endpoint(tcp::v4(), 1337)};
    tcp::socket ssock{sios};
    std::thread sthread([&]{
        acc.accept(ssock);
    });

    asio::io_service cios;
    tcp::socket csock{cios};
    tcp::resolver resolver{cios};
    asio::connect(csock, resolver.resolve({"127.0.0.1", "1337"}));

    sthread.join();

    std::array<uint8_t, 32> key;
    cry::random_data(key);

    Channel schan{std::move(ssock)};
    schan.set_key(key);
    Channel cchan{std::move(csock)};
    cchan.set_key(key);

    std::vector<uint8_t> msg{0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    for(int i = 0; i < 5; ++i)
        cchan.send(msg);

    for(int i = 0; i < 5; ++i)
        REQUIRE(schan.recv() == msg);
    REQUIRE(schan.try_recv() == std::vector<uint8_t>{});

    cry::random_data(key);
    cchan.set_key(key);
    for(int i = 0; i < 5; ++i)
        cchan.send(msg);

    for(int i = 0; i < 5; ++i)
        REQUIRE(!(schan.recv() == msg));
    REQUIRE(schan.try_recv() == std::vector<uint8_t>{});
}
