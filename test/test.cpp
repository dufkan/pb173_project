#include "../server/server.hpp"
#include "../client/client.hpp"

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "test_crypto.cpp"
#include "test_server.cpp"

TEST_CASE("Challenge-Response") {

    // TODO REFACTOR!

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

    std::string pseudo = "TEST";
    std::vector<uint8_t> cchal = c.client_challenge(Rc, spub, pseudo, {});

    Decoder d{cchal};
    std::vector<uint8_t> parsed_eRc = d.get_vec(512);
    std::vector<uint8_t> parsed_payload = d.get_vec();


    auto dRc = cry::decrypt_rsa(parsed_eRc, spriv);
    std::array<uint8_t, 32> dRca;
    std::copy(dRc.data(), dRc.data() + 32, dRca.data());
    REQUIRE(dRca == Rc); // Rc transfer ok

    auto payload = cry::decrypt_aes(parsed_payload, {}, dRca);
    Decoder dp{payload};
    auto plen = dp.get_u16();
    auto ps = dp.get_str(plen);
    auto klen = dp.get_u16();
    auto key = dp.get_vec(klen);

    REQUIRE(plen == 4);
    REQUIRE(ps == pseudo);

    std::array<uint8_t, 32> Rs;
    cry::random_data(Rs);
    auto schal = s.server_chr(Rs, Rc, cpub);

    Decoder ds{schal};
    auto parsed_eRs = ds.get_vec(512);
    auto parsed_payloads = ds.get_vec();

    auto dRs = cry::decrypt_rsa(parsed_eRs, cpriv);
    std::array<uint8_t, 32> dRsa;
    std::copy(dRs.data(), dRs.data() + 32, dRsa.data());
    REQUIRE(dRsa == Rs); // Rs transfer ok

    auto payloads = cry::decrypt_aes(parsed_payloads, {}, dRsa);
    Decoder dps{payloads};
    auto dunno = dps.get_vec();
    std::array<uint8_t, 32> Rc_verify;
    std::copy(dunno.data(), dunno.data() + 32, Rc_verify.data());
    REQUIRE(Rc_verify == Rc); // Server authenticated

    Encoder e;
    e.put(Rs);
    e.put(Rc);
    auto K = cry::hash_sha(e.move());

    auto fin = c.client_response(K, Rs);
    auto ok = cry::decrypt_aes(fin, {}, K);
    std::array<uint8_t, 32> Rs_verify;
    std::copy(ok.data(), ok.data() + 32, Rs_verify.data());
    REQUIRE(Rs_verify == Rs); // Client authenticated
}
