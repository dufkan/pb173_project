#include "../shared/crypto.hpp"

TEST_CASE("test_padding","function cry::pad, cry::unpad - 'abc'") {
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

TEST_CASE("AES-256 CBC test vectors", "first") {
    std::array<uint8_t, 32> key = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
    std::array<uint8_t, 16> iv = {{0xF5, 0x8C, 0x4C, 0x04, 0xD6, 0xE5, 0xF1, 0xBA, 0x77, 0x9E, 0xAB, 0xFB, 0x5F, 0x7B, 0xFB, 0xD6}};
    std::vector<uint8_t> plaintext = {0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
    std::vector<uint8_t> ciphertext = {0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d};


    std::array<uint8_t, 16> iv2 = {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}};
    std::vector<uint8_t> plaintext2 = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    std::vector<uint8_t> ciphertext2 = {0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6};

    std::array<uint8_t, 16> iv3 = {{0x9C, 0xFC, 0x4E, 0x96, 0x7E, 0xDB, 0x80, 0x8D, 0x67, 0x9F, 0x77, 0x7B, 0xC6, 0x70, 0x2C, 0x7D}};
    std::vector<uint8_t> plaintext3 = {0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef};
    std::vector<uint8_t> ciphertext3 = {0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61};


    std::array<uint8_t, 16> iv4 = {{0x39, 0xF2, 0x33, 0x69, 0xA9, 0xD9, 0xBA, 0xCF, 0xA5, 0x30, 0xE2, 0x63, 0x04, 0x23, 0x14, 0x61}};
    std::vector<uint8_t> plaintext4 = {0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    std::vector<uint8_t> ciphertext4 = {0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b};

    SECTION("encryption") {
	auto enc = cry::encrypt_aes(plaintext, iv, key);
     	auto enc2 = cry::encrypt_aes(plaintext2, iv2, key);
	auto enc3 = cry::encrypt_aes(plaintext3, iv3, key);
	auto enc4 = cry::encrypt_aes(plaintext4, iv4, key);
	REQUIRE(memcmp(enc.data(),ciphertext.data(),ciphertext.size())==0);
	REQUIRE(memcmp(enc2.data(), ciphertext2.data(), ciphertext2.size())==0);
	REQUIRE(memcmp(enc3.data(), ciphertext3.data(),ciphertext3.size())==0);
	REQUIRE(memcmp(enc4.data(),ciphertext4.data(),ciphertext4.size())==0);
    }

    SECTION("decryption") {
        REQUIRE(cry::decrypt_aes(ciphertext, iv, key) == plaintext);
	REQUIRE(cry::decrypt_aes(ciphertext2, iv2, key) == plaintext2);
	REQUIRE(cry::decrypt_aes(ciphertext3, iv3, key) == plaintext3);
	REQUIRE(cry::decrypt_aes(ciphertext4, iv4, key) == plaintext4);
    }
}


TEST_CASE("SHA2-256 test vectors") {
    std::vector<uint8_t> abc = {0x61, 0x62, 0x63};
    std::array<uint8_t,32> hash_abc = {{0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}};

    std::vector<uint8_t> empty = {};
    std::array<uint8_t,32> hash_empty = {{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55}};

    std::vector<uint8_t> a1M = {};
    a1M.resize(1000000, 0x61);
    std::array<uint8_t,32> hash_a1M = {{0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0}};

    SECTION("Create hash") {
        CHECK(cry::hash_sha(abc) == hash_abc);
        CHECK(cry::hash_sha(empty) == hash_empty);
        CHECK(cry::hash_sha(a1M) == hash_a1M);
    }

    SECTION("Check hash"){
	CHECK(cry::check_hash(abc,hash_abc));
	CHECK(cry::check_hash(empty,hash_empty));
	CHECK(cry::check_hash(a1M,hash_a1M));
    }
}

TEST_CASE("Generating RSA keys", "Testing public and private keys") {
    mbedtls_rsa_context priv, pub;
        
    mbedtls_rsa_init(&pub, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    mbedtls_rsa_init(&priv, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    cry::generate_rsa_keys(&pub,&priv);
    
    CHECK(mbedtls_rsa_check_pubkey(&pub)==0);
    CHECK(mbedtls_rsa_check_privkey(&priv)==0);
    CHECK(mbedtls_rsa_check_pub_priv(&pub, &priv)==0);
    
    mbedtls_rsa_free(&pub);
    mbedtls_rsa_free(&priv);
}


TEST_CASE("Get random data", "Get some data") {
    std::vector<uint8_t> v1 = cry::get_random_data((size_t) 256);
    std::vector<uint8_t> v2 = cry::get_random_data((size_t) 256);
    std::vector<uint8_t> v11 = v1;

    CHECK(v1.size()==256);
    CHECK(v1 != v2);
    v1 = cry::get_random_data(5);
    CHECK(v11 != v1);
    CHECK(v1.size() == 5);
}



TEST_CASE("Encryption/decryption using RSA 2048","Test using function for generating keys"){
    mbedtls_rsa_context priv, pub;
    
    mbedtls_rsa_init(&pub, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    mbedtls_rsa_init(&priv, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    
    cry::generate_rsa_keys(&pub, &priv);
    
    CHECK(mbedtls_rsa_check_pubkey(&pub)==0);
    CHECK(mbedtls_rsa_check_privkey(&priv)==0);
    CHECK(mbedtls_rsa_check_pub_priv(&pub, &priv)==0);

    std::vector<uint8_t> pl = cry::get_random_data((size_t) 250);
    std::vector<uint8_t> pl2 = {0x28, 0x35, 0x46}; 
    
    std::vector<uint8_t> cip = cry::encrypt_rsa(pl, &pub);
    std::vector<uint8_t> cip2 = cry::encrypt_rsa(pl2, &pub);
    
    std::vector<uint8_t> dec = cry::decrypt_rsa(cip,&priv);
    std::vector<uint8_t> dec2 = cry::decrypt_rsa(cip2,&priv);
    CHECK(memcmp(pl.data(),dec.data(),pl.size())==0);
    
    CHECK(memcmp(pl2.data(),dec2.data(),pl2.size())==0);

    mbedtls_rsa_free(&pub);
    mbedtls_rsa_free(&priv);

} 


TEST_CASE("MAC data","genereting and checking") {
    std::vector<uint8_t> data = cry::get_random_data((size_t) 256);
    std::array<uint8_t,32> data2 = {*(data.data())};
    std::array<uint8_t,32> mac_output = cry::mac_data(data,data2);

    CHECK(cry::check_mac(data, data2, mac_output));
}
