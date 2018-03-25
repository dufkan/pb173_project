#include "../server/server.hpp"
#include "../client/client.hpp"

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "test_crypto.cpp"
#include "test_server.cpp"

TEST_CASE("Challenge-Response") {
    Server s;
    Client c;
}
