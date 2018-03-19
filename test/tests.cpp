#include "../server/server.hpp"

#ifndef CATCH_CONFIG_MAIN
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#endif

TEST_CASE("File IO", "[file]") {
    SECTION("Read") {
        REQUIRE_THROWS(read_file("noread"));
        REQUIRE_THROWS(read_file("noexist"));
        REQUIRE_NOTHROW(read_file("nowrite"));
    }
    SECTION("Write") {
        REQUIRE_THROWS(write_file("nowrite", {0x00, 0x01, 0x02}));
        REQUIRE_NOTHROW(write_file("noexist", {0x00, 0x01, 0x02}));
        REQUIRE_NOTHROW(write_file("noread", {0x00, 0x01, 0x02}));
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
    Server s;
    s.connections.insert(std::make_pair(std::string{"eve"}, Channel{}));
    s.connections.insert(std::make_pair(std::string{"alice"}, Channel{}));
    s.connections.insert(std::make_pair(std::string{"bob"}, Channel{}));
    REQUIRE(s.get_connected_users() == std::vector<std::string>{"alice", "bob", "eve"});
}
