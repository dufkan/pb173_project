#include "../server/server.hpp"
#include "../client/client.hpp"
#include "../shared/crypto.hpp"

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

cry::RSAKey SERVER_KEY;
cry::RSAKey CLIENT_KEY;

int main(int argc, char** argv) {
    cry::generate_rsa_keys(SERVER_KEY, SERVER_KEY);
    cry::generate_rsa_keys(CLIENT_KEY, CLIENT_KEY);
    return Catch::Session().run(argc, argv);
}

#include "test_crypto.cpp"
#include "test_server.cpp"
#include "test_messages.cpp"
#include "test_channel.cpp"
#include "test_client.cpp"
#include "test_crybox.cpp"
#include "test_communication.cpp"

TEST_CASE("Challenge-Response") {
    msg::MessageDeserializer md;

    Client c;
    Server s;

    std::array<uint8_t, 32> Rc;
    cry::random_data(Rc);

    std::string pseudonym = "TEST";
    msg::ClientInit cinit{pseudonym, Rc, CLIENT_KEY.export_pub()};
    cinit.encrypt(SERVER_KEY);
    auto uniq_cinit = md(cinit.serialize());
    auto real_cinit = dynamic_cast<msg::ClientInit&>(*uniq_cinit.get());
    real_cinit.decrypt(SERVER_KEY);
    auto [server_Rc, server_pseudonym, server_key] = real_cinit.get();

    REQUIRE(server_Rc == Rc); // Rc transfer successful
    REQUIRE(server_pseudonym == pseudonym);

    std::array<uint8_t, 32> Rs;
    cry::random_data(Rs);

    msg::ServerResp sresp{Rs, Rc};
    sresp.encrypt(CLIENT_KEY);
    auto uniq_sresp = md(sresp.serialize());
    auto real_sresp = dynamic_cast<msg::ServerResp&>(*uniq_sresp.get());
    real_sresp.decrypt(CLIENT_KEY);
    auto [client_Rs, verify_Rc] = real_sresp.get();

    REQUIRE(Rs == client_Rs); // Rs transfer successful
    REQUIRE(verify_Rc == Rc); // server authenticated

    Encoder e;
    e.put(Rs);
    e.put(Rc);
    auto K = cry::hash_sha(e.move());

    msg::ClientResp cresp{Rs};
    cresp.encrypt(K);
    auto uniq_cresp = md(cresp.serialize());
    auto real_cresp = dynamic_cast<msg::ClientResp&>(*uniq_cresp.get());
    real_cresp.decrypt(K);
    auto verify_Rs = real_cresp.get();
    REQUIRE(verify_Rs == Rs); // client authenticated
}
