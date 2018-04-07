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
        REQUIRE(add_user("u" + std::to_string(i), {0x01, 0x02, 0x03, 0x04}));
        REQUIRE(!add_user("u" + std::to_string(i), {0x01, 0x02, 0x03, 0x04}));
    }

    for(uint8_t i = 0; i < 10; ++i) 
        remove_user("u" + std::to_string(i));
}

TEST_CASE("Remove user") {
    for(uint8_t i = 0; i < 10; ++i)
        add_user("u" + std::to_string(i), {0x01, 0x02, 0x03, 0x04});

    for(uint8_t i = 0; i < 10; ++i) {
        REQUIRE(remove_user("u" + std::to_string(i)));
        REQUIRE(!remove_user("u" + std::to_string(i)));
    }
}

TEST_CASE("Get user key") {
    for(uint8_t i = 0; i < 10; ++i)
        add_user("u" + std::to_string(i), std::vector<uint8_t>{static_cast<uint8_t>(0x01 + i), static_cast<uint8_t>(0x02 * i), static_cast<uint8_t>(i % 0x03), static_cast<uint8_t>(0x04 % (i + 1))});

    for(uint8_t i = 0; i < 10; ++i)
        REQUIRE(get_user("u" + std::to_string(i)) == std::vector<uint8_t>{static_cast<uint8_t>(0x01 + i), static_cast<uint8_t>(0x02 * i), static_cast<uint8_t>(i % 0x03), static_cast<uint8_t>(0x04 % (i + 1))});
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
    SECTION("with connected user") {
        // TODO requires implementation of dummy channel, not sure if worth it though
    }
    SECTION("without connected user") {
        Server s;
        s.handle_send("bob", msg::Send{"alice", std::vector<uint8_t>{0x60, 0x61, 0x62, 0x63}});

        msg::Recv msg = s.message_queue["alice"].front();
        s.message_queue["alice"].pop();

        REQUIRE(msg.get_sender() == "bob");
        REQUIRE(msg.get_text() == std::vector<uint8_t>{0x60, 0x61, 0x62, 0x63});
        REQUIRE(s.message_queue["alice"].empty());
    }
    SECTION("multiple without connected user") {
        Server s;
        s.handle_send("bob", msg::Send{"alice", std::vector<uint8_t>{0x60, 0x61, 0x62, 0x63}});
        s.handle_send("eve", msg::Send{"alice", std::vector<uint8_t>{0x66, 0x60}});
        s.handle_send("bob", msg::Send{"alice", std::vector<uint8_t>{0x61, 0x61, 0x62, 0x63}});

        msg::Recv msg = s.message_queue["alice"].front();
        s.message_queue["alice"].pop();
        REQUIRE(msg.get_sender() == "bob");
        REQUIRE(msg.get_text() == std::vector<uint8_t>{0x60, 0x61, 0x62, 0x63});

        msg = s.message_queue["alice"].front();
        s.message_queue["alice"].pop();
        REQUIRE(msg.get_sender() == "eve");
        REQUIRE(msg.get_text() == std::vector<uint8_t>{0x66, 0x60});

        msg = s.message_queue["alice"].front();
        s.message_queue["alice"].pop();
        REQUIRE(msg.get_sender() == "bob");
        REQUIRE(msg.get_text() == std::vector<uint8_t>{0x61, 0x61, 0x62, 0x63});

        REQUIRE(s.message_queue["alice"].empty());
    }
}
