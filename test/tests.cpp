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
    for(int i = 0; i < 10; ++i) {
        REQUIRE(add_user("u" + std::to_string(i), {0x01, 0x02, 0x03, 0x04}));
        REQUIRE(!add_user("u" + std::to_string(i), {0x01, 0x02, 0x03, 0x04}));
    }
}
