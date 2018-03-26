#include "../server/server.hpp"
#include "../client/client.hpp"

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "test_crypto.cpp"
#include "test_server.cpp"

TEST_CASE("Challenge-Response") {
    Client c;
    Server s;

    mbedtls_rsa_context spub[1], spriv[1];
    mbedtls_rsa_context cpub[1], cpriv[1];
    mbedtls_rsa_init(spub, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    mbedtls_rsa_init(spriv, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    mbedtls_rsa_init(cpub, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    mbedtls_rsa_init(cpriv, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    cry::generate_rsa_keys(spub, spriv);
    cry::generate_rsa_keys(cpub, cpriv);


    std::array<uint8_t, 32> Rc;
    cry::random_data(Rc);

    std::string pseudonym = "TEST";
    auto client_challenge = c.client_challenge(Rc, spub, pseudonym, {});
    auto [server_Rc, server_pseudonym, server_key] = s.decode_client_challenge(client_challenge, spriv);

    REQUIRE(server_Rc == Rc); // Rc transfer successful
    REQUIRE(server_pseudonym == pseudonym);

    std::array<uint8_t, 32> Rs;
    cry::random_data(Rs);

    auto server_challenge = s.server_chr(Rs, server_Rc, cpub);
    auto [client_Rs, verify_Rc] = c.decode_server_chr(server_challenge, cpriv);

    REQUIRE(Rs == client_Rs); // Rs transfer successful
    REQUIRE(verify_Rc == Rc); // server authenticated

    Encoder e;
    e.put(Rs);
    e.put(Rc);
    auto K = cry::hash_sha(e.move());

    auto client_response = c.client_response(K, Rs);
    auto verify_Rs = s.decode_client_response(client_response, K);
    REQUIRE(verify_Rs == Rs); // client authenticated
}
