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
    cry::RSAKey priv, pub;

    cry::generate_rsa_keys(pub, priv);

    CHECK(pub.has_pub());
    CHECK(!pub.has_priv());
    CHECK(priv.has_pub());
    CHECK(priv.has_priv());
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
    cry::RSAKey priv, pub;

    cry::generate_rsa_keys(pub, priv);

    CHECK(pub.has_pub());
    CHECK(!pub.has_priv());
    CHECK(priv.has_pub());
    CHECK(priv.has_priv());

    std::vector<uint8_t> pl;
    pl.resize(250);
    cry::random_data(pl);
    std::vector<uint8_t> pl2 = {0x28, 0x35, 0x46};

    std::vector<uint8_t> cip = cry::encrypt_rsa(pl, pub);
    std::vector<uint8_t> cip2 = cry::encrypt_rsa(pl2, pub);

    std::vector<uint8_t> dec = cry::decrypt_rsa(cip, priv);
    std::vector<uint8_t> dec2 = cry::decrypt_rsa(cip2, priv);
    CHECK(memcmp(pl.data(),dec.data(),pl.size())==0);
    CHECK(memcmp(pl2.data(),dec2.data(),pl2.size())==0);
}


TEST_CASE("MAC data","genereting and checking") {
    std::vector<uint8_t> data = cry::get_random_data((size_t) 256);
    std::array<uint8_t,32> K;
    cry::random_data(K);
    std::array<uint8_t,32> mac_output = cry::mac_data(data, K);

    CHECK(cry::check_mac(data, K, mac_output));
}

TEST_CASE("RSAKey") {
    cry::RSAKey k;
    cry::RSAKey kpub;
    cry::RSAKey kpriv;

    REQUIRE(!k.has_pub());
    REQUIRE(!k.has_priv());

    cry::generate_rsa_keys(k, k);
    cry::generate_rsa_keys(kpub, kpriv);

    REQUIRE(k.has_pub());
    REQUIRE(k.has_priv());

    REQUIRE(kpub.has_pub());
    REQUIRE(!kpub.has_priv());

    REQUIRE(kpriv.has_pub());
    REQUIRE(kpriv.has_priv());
}

TEST_CASE("RSA import and export") {
    cry::RSAKey k, l, m;
    cry::generate_rsa_keys(k, k);

    REQUIRE(!l.has_pub());
    REQUIRE(!l.has_priv());

    REQUIRE(!k.is_correct_priv(l));
    REQUIRE(!l.is_correct_priv(k));

    auto exported = k.export_all();
    l.import(exported);

    REQUIRE(l.has_pub());
    REQUIRE(l.has_priv());

    REQUIRE(k.is_correct_priv(l));
    REQUIRE(l.is_correct_priv(k));

    exported = k.export_pub();
    m.import(exported);

    REQUIRE(m.has_pub());
    REQUIRE(!m.has_priv());

    REQUIRE(k.is_correct_priv(m));
    REQUIRE(!m.is_correct_priv(k));
}





TEST_CASE("ECDH generating public and private keys") {
    cry::ECKey k;
    k.gen_pub_key();
    REQUIRE(k.has_pub());
    REQUIRE(k.has_priv());
    REQUIRE(k.is_correct_priv(k));

    cry::ECKey k2(k);
    REQUIRE(k2.has_pub());
    REQUIRE(k2.has_priv());
    REQUIRE(k2.is_correct_priv(k));

    cry::ECKey k3 = k;
    REQUIRE(k3.has_pub());
    REQUIRE(k3.has_priv());
    REQUIRE(k3.is_correct_priv(k));

    REQUIRE(k == k2);
    REQUIRE(k == k3);
}


TEST_CASE("ECDH - share secret") {
    cry::ECKey k;
    cry::ECKey l;

    k.gen_pub_key();
    l.gen_pub_key();

    std::array<uint8_t,32> kq = k.get_bin_q();
    std::array<uint8_t,32> lq = l.get_bin_q();

    k.load_bin_qp(lq);
    l.load_bin_qp(kq);

    k.compute_shared();
    l.compute_shared();

    REQUIRE(l != k );
    REQUIRE(k.compare_shared(*(l.get())));
    
    std::array<uint8_t,32> sk = k.get_shared();
    std::array<uint8_t,32> sl = l.get_shared();
    REQUIRE(sk==sl);

    k.gen_pub_key();
    REQUIRE(k.get_bin_q() != kq);
    REQUIRE(k.compare_point(&k.ctx.Qp,&l.ctx.Q));
    REQUIRE(k.get_shared() == sk);
}


TEST_CASE("ECKey - get and load binary") {
    std::vector<uint8_t> data; 
    cry::ECKey k;
    cry::ECKey new_k;
    k.gen_pub_key();

    data = k.get_key_binary();
    new_k.load_key_binary(data);
    
    CHECK(new_k.has_priv());
    CHECK(new_k.has_pub());
    CHECK(new_k.is_correct_priv(k));
    CHECK(mbedtls_ecp_check_pubkey(&new_k.get()->grp,&new_k.get()->Q)==0);
    REQUIRE( k == new_k);    
}

TEST_CASE("PRNG") {
    cry::PRNG a;
    cry::PRNG b;

    REQUIRE(cry::defprng.k != a.k);
    REQUIRE(cry::defprng.v != b.v);
    REQUIRE(a.k != b.k);
    REQUIRE(a.v != b.v);

    for(int i = 0; i < 1000; ++i) {
        REQUIRE(a.next() != b.next());
        REQUIRE(a.v != b.v);
    }

    for(int i = 0; i < 1000; ++i) {
        std::array<uint8_t, 32> arr_a{};
        std::array<uint8_t, 32> arr_b{};
        std::array<uint8_t, 32> arr_def{};
        a.random_data(arr_a);
        b.random_data(arr_b);
        cry::defprng.random_data(arr_def);
        REQUIRE(arr_a != arr_b);
        REQUIRE(arr_a != arr_def);
    }

    for(int i = 0; i < 1000; ++i) {
        std::array<uint8_t, 32> arr_a{};
        std::array<uint8_t, 32> arr_b{};
        std::array<uint8_t, 32> arr_def{};
        a.random_bytes(arr_a.data(), 32);
        b.random_bytes(arr_b.data(), 32);
        cry::defprng.random_bytes(arr_def.data(), 32);
        REQUIRE(arr_a != arr_b);
        REQUIRE(arr_a != arr_def);
    }

    for(int i = 0; i < 1000; ++i) {
        std::array<uint8_t, 31> arr_a{};
        std::array<uint8_t, 31> arr_b{};
        std::array<uint8_t, 31> arr_def{};
        a.random_bytes(arr_a.data(), 31);
        b.random_bytes(arr_b.data(), 31);
        cry::defprng.random_bytes(arr_def.data(), 31);
        REQUIRE(arr_a != arr_b);
        REQUIRE(arr_a != arr_def);
    }
}

TEST_CASE("Elliptic Signatures") {
    cry::ECKey k;
    k.gen_pub_key();

    SECTION("empty") {
        std::vector<uint8_t> data = {};
        auto sig = cry::sign_ec(data, k);
        //REQUIRE(cry::verify_ec(data, sig, k.get_bin_q()));
        sig[0] += 7;
        //REQUIRE(!cry::verify_ec(data, sig, k.get_bin_q()));
    }
    SECTION("some") {
        std::vector<uint8_t> data = {'T', 'e', 's', 't', ' ', 0x00, 0x01, 0x02, 0x03, 0x04};
        auto sig = cry::sign_ec(data, k);
        //REQUIRE(cry::verify_ec(data, sig, k.get_bin_q()));
        sig[0] += 7;
        //REQUIRE(!cry::verify_ec(data, sig, k.get_bin_q()));
    }
    SECTION("a lot") {
        std::vector<uint8_t> data;
        data.resize(1024 * 1024);
        std::iota(data.begin(), data.end(), 0);
        auto sig = cry::sign_ec(data, k);
        //REQUIRE(cry::verify_ec(data, sig, k.get_bin_q()));
        sig[0] += 7;
        //REQUIRE(!cry::verify_ec(data, sig, k.get_bin_q()));
    }
}

TEST_CASE("KDF") {
    B32 pass;
    std::iota(pass.begin(), pass.end(), 0);
    B16 salt;
    std::iota(salt.begin(), salt.end(), 0x80);

    B32 derived = cry::kdf(pass, salt);

    for(int i = 0; i < 46; ++i)
        REQUIRE(derived == cry::kdf(pass, salt));

    pass[0] += 1;
    REQUIRE(derived != cry::kdf(pass, salt));
    pass[0] -= 1;
    REQUIRE(derived == cry::kdf(pass, salt));
    salt[0] += 1;
    REQUIRE(derived != cry::kdf(pass, salt));
}
