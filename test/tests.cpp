#include "../server/server.hpp"
#include "../shared/crypto.hpp"

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


TEST_CASE("Pad and unpad","crypto.hpp") {
    std::vector<uint8_t> v1 = {0x61, 0x62, 0x63};
    std::vector<uint8_t> v2 = v1;
    cry::pad(v1,(uint8_t) 16);
    CHECK(v1.size()==16);

    cry::unpad(v1,16);
    CHECK(v1.size()==3);
    CHECK(v1==v2);

    cry::pad(v1,(uint8_t) 2);
    CHECK(v1.size()==4);

    cry::unpad(v1,2);
    CHECK(v1.size()==3);
    CHECK(v1==v2);

    cry::pad(v1,(uint8_t) 32);
    CHECK(v1.size()==32);

    cry::unpad(v1,32);
    CHECK(v1.size()==3);
    CHECK(v1==v2);
}


TEST_CASE("AES-256 CBC test vectors") {
    std::array<uint8_t, 32> key = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
    std::array<uint8_t, 16> iv = {{0xF5, 0x8C, 0x4C, 0x04, 0xD6, 0xE5, 0xF1, 0xBA, 0x77, 0x9E, 0xAB, 0xFB, 0x5F, 0x7B, 0xFB, 0xD6}};
    std::vector<uint8_t> plaintext = {0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
    std::vector<uint8_t> ciphertext = {0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d};

    SECTION("encryption") {
        REQUIRE(cry::encrypt_aes(plaintext, iv, key) == ciphertext);
    }

    SECTION("decryption") {
        REQUIRE(cry::decrypt_aes(ciphertext, iv, key) == plaintext);
    }
}

