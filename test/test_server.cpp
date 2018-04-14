#include "../server/server.hpp"

TEST_CASE("File IO", "[file]") {
    SECTION("Read") {
        REQUIRE_THROWS(util::read_file("noread"));
        REQUIRE_THROWS(util::read_file("noexist"));
        REQUIRE_NOTHROW(util::read_file("nowrite"));
    }
    SECTION("Write") {
        REQUIRE_THROWS(util::write_file("nowrite", {0x00, 0x01, 0x02}));
        REQUIRE_NOTHROW(util::write_file("noexist", {0x00, 0x01, 0x02}));
        REQUIRE_NOTHROW(util::write_file("noread", {0x00, 0x01, 0x02}));
    }
}

TEST_CASE("Add user") {
    for(uint8_t i = 0; i < 10; ++i) {
        REQUIRE(Server::store_client_key("u" + std::to_string(i), {0x01, 0x02, 0x03, 0x04}));
        REQUIRE(!Server::store_client_key("u" + std::to_string(i), {0x01, 0x02, 0x03, 0x04}));
    }

    for(uint8_t i = 0; i < 10; ++i) 
        Server::remove_client_key("u" + std::to_string(i));
}

TEST_CASE("Remove user") {
    for(uint8_t i = 0; i < 10; ++i)
        Server::store_client_key("u" + std::to_string(i), {0x01, 0x02, 0x03, 0x04});

    for(uint8_t i = 0; i < 10; ++i) {
        REQUIRE(Server::remove_client_key("u" + std::to_string(i)));
        REQUIRE(!Server::remove_client_key("u" + std::to_string(i)));
    }
}

TEST_CASE("Get user key") {
    for(uint8_t i = 0; i < 10; ++i)
        Server::store_client_key("u" + std::to_string(i), std::vector<uint8_t>{static_cast<uint8_t>(0x01 + i), static_cast<uint8_t>(0x02 * i), static_cast<uint8_t>(i % 0x03), static_cast<uint8_t>(0x04 % (i + 1))});

    for(uint8_t i = 0; i < 10; ++i)
        REQUIRE(Server::load_client_key("u" + std::to_string(i)) == std::vector<uint8_t>{static_cast<uint8_t>(0x01 + i), static_cast<uint8_t>(0x02 * i), static_cast<uint8_t>(i % 0x03), static_cast<uint8_t>(0x04 % (i + 1))});
}

TEST_CASE("Get active user vector") {
    asio::io_service io_service;
    asio::ip::tcp::socket sock{io_service};
    Server s;
    s.connections.insert(std::make_pair(std::string{"eve"}, Channel{std::move(sock)}));
    s.connections.insert(std::make_pair(std::string{"alice"}, Channel{std::move(sock)}));
    s.connections.insert(std::make_pair(std::string{"bob"}, Channel{std::move(sock)}));
    REQUIRE(s.get_connected_users() == std::vector<std::string>{"alice", "bob", "eve"});
}

TEST_CASE("Handle Send") {
    msg::MessageDeserializer md;
    SECTION("with connected user") {
        // TODO requires implementation of dummy channel, not sure if worth it though
    }
    SECTION("without connected user") {
        Server s;
        s.handle_send("bob", msg::Send{"alice", std::vector<uint8_t>{0x60, 0x61, 0x62, 0x63}});

        std::vector<uint8_t> smsg = s.message_queue["alice"].front();
        s.message_queue["alice"].pop();

        auto dmsg = md(smsg);
        auto& msg = dynamic_cast<msg::Recv&>(*dmsg.get());

        REQUIRE(msg.get_sender() == "bob");
        REQUIRE(msg.get_text() == std::vector<uint8_t>{0x60, 0x61, 0x62, 0x63});
        REQUIRE(s.message_queue["alice"].empty());
    }
    SECTION("multiple without connected user") {
        Server s;
        s.handle_send("bob", msg::Send{"alice", std::vector<uint8_t>{0x60, 0x61, 0x62, 0x63}});
        s.handle_send("eve", msg::Send{"alice", std::vector<uint8_t>{0x66, 0x60}});
        s.handle_send("bob", msg::Send{"alice", std::vector<uint8_t>{0x61, 0x61, 0x62, 0x63}});

        std::vector<uint8_t> smsg = s.message_queue["alice"].front();
        s.message_queue["alice"].pop();
        auto dmsg = md(smsg);
        auto& m1 = dynamic_cast<msg::Recv&>(*dmsg.get());
        REQUIRE(m1.get_sender() == "bob");
        REQUIRE(m1.get_text() == std::vector<uint8_t>{0x60, 0x61, 0x62, 0x63});

        smsg = s.message_queue["alice"].front();
        s.message_queue["alice"].pop();
        dmsg = md(smsg);
        auto& m2 = dynamic_cast<msg::Recv&>(*dmsg.get());
        REQUIRE(m2.get_sender() == "eve");
        REQUIRE(m2.get_text() == std::vector<uint8_t>{0x66, 0x60});

        smsg = s.message_queue["alice"].front();
        s.message_queue["alice"].pop();
        dmsg = md(smsg);
        auto& m3 = dynamic_cast<msg::Recv&>(*dmsg.get());
        REQUIRE(m3.get_sender() == "bob");
        REQUIRE(m3.get_text() == std::vector<uint8_t>{0x61, 0x61, 0x62, 0x63});

        REQUIRE(s.message_queue["alice"].empty());
    }
}
