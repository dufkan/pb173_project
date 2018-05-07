#include "../shared/crybox.hpp"
#include <numeric>

TEST_CASE("IdBox"){
    IdBox box;
    SECTION("empty") {
        std::vector<uint8_t> data = {};
        REQUIRE(box.encrypt(data) == data);
        REQUIRE(box.decrypt(data) == data);
        REQUIRE(box.decrypt(box.encrypt(data)) == data);
    }
    SECTION("some") {
        std::vector<uint8_t> data = {'T', 'e', 's', 't', ' ', 0x00, 0x01, 0x02, 0x03, 0x04};
        REQUIRE(box.encrypt(data) == data);
        REQUIRE(box.decrypt(data) == data);
        REQUIRE(box.decrypt(box.encrypt(data)) == data);
    }
    SECTION("a lot") {
        std::vector<uint8_t> data;
        data.resize(1024 * 1024);
        std::iota(data.begin(), data.end(), 0);
        REQUIRE(box.encrypt(data) == data);
        REQUIRE(box.decrypt(data) == data);
        REQUIRE(box.decrypt(box.encrypt(data)) == data);
    }
}

TEST_CASE("AESBox"){
    std::array<uint8_t, 32> K;
    std::for_each(K.begin(), K.end(), [](uint8_t x){ return x * x + 1; });
    AESBox box{K};
    SECTION("empty") {
        std::vector<uint8_t> data = {};
        REQUIRE(box.encrypt(data) == cry::encrypt_aes(data, {}, K));
        REQUIRE(box.decrypt(box.encrypt(data)) == cry::decrypt_aes(cry::encrypt_aes(data, {}, K), {}, K));
        REQUIRE(box.decrypt(box.encrypt(data)) == data);
    }
    SECTION("some") {
        std::vector<uint8_t> data = {'T', 'e', 's', 't', ' ', 0x00, 0x01, 0x02, 0x03, 0x04};
        REQUIRE(box.encrypt(data) == cry::encrypt_aes(data, {}, K));
        REQUIRE(box.decrypt(box.encrypt(data)) == cry::decrypt_aes(cry::encrypt_aes(data, {}, K), {}, K));
        REQUIRE(box.decrypt(box.encrypt(data)) == data);
    }
    SECTION("a lot") {
        std::vector<uint8_t> data;
        data.resize(1024 * 1024);
        std::iota(data.begin(), data.end(), 0);
        REQUIRE(box.encrypt(data) == cry::encrypt_aes(data, {}, K));
        REQUIRE(box.decrypt(box.encrypt(data)) == cry::decrypt_aes(cry::encrypt_aes(data, {}, K), {}, K));
        REQUIRE(box.decrypt(box.encrypt(data)) == data);
    }
}

TEST_CASE("MACBox"){
    std::array<uint8_t, 32> K{};
    std::iota(K.begin(), K.end(), 0);
    MACBox box{K};
    std::array<uint8_t, 32> SK = cry::hash_sha(K);
    SECTION("empty") {
        std::vector<uint8_t> data = {};
        std::vector<uint8_t> macd = data;

        std::array<uint8_t, 32> mac = cry::mac_data(data, SK);
        macd.insert(macd.end(), mac.begin(), mac.end());

        REQUIRE(box.encrypt(data) == macd);
        REQUIRE(box.decrypt(macd) == data);
        REQUIRE(box.decrypt(box.encrypt(data)) == data);

        macd[0] += 1;
        REQUIRE_THROWS(box.decrypt(macd));
    }
    SECTION("some") {
        std::vector<uint8_t> data = {'T', 'e', 's', 't', ' ', 0x00, 0x01, 0x02, 0x03, 0x04};
        std::vector<uint8_t> macd = data;

        std::array<uint8_t, 32> mac = cry::mac_data(data, SK);
        macd.insert(macd.end(), mac.begin(), mac.end());

        REQUIRE(box.encrypt(data) == macd);
        REQUIRE(box.decrypt(macd) == data);
        REQUIRE(box.decrypt(box.encrypt(data)) == data);

        macd[0] += 1;
        REQUIRE_THROWS(box.decrypt(macd));
    }
    SECTION("a lot") {
        std::vector<uint8_t> data;
        data.resize(1024 * 1024);
        std::iota(data.begin(), data.end(), 0);
        std::vector<uint8_t> macd = data;

        std::array<uint8_t, 32> mac = cry::mac_data(data, SK);
        macd.insert(macd.end(), mac.begin(), mac.end());

        REQUIRE(box.encrypt(data) == macd);
        REQUIRE(box.decrypt(macd) == data);
        REQUIRE(box.decrypt(box.encrypt(data)) == data);

        macd[0] += 1;
        REQUIRE_THROWS(box.decrypt(macd));
    }
}

TEST_CASE("SeqBox single") {
    std::array<uint8_t, 32> K;
    std::for_each(K.begin(), K.end(), [](uint8_t x){ return x * x + 1; });
    SeqBox box = std::unique_ptr<CryBox>{new AESBox{K}};
    AESBox abox{K};

    SECTION("empty") {
        std::vector<uint8_t> data = {};
        std::vector<uint8_t> enc = box.encrypt(data);
        REQUIRE(enc == abox.encrypt(data));
        REQUIRE(box.decrypt(enc) == abox.decrypt(enc));
    }
    SECTION("some") {
        std::vector<uint8_t> data = {'T', 'e', 's', 't', ' ', 0x00, 0x01, 0x02, 0x03, 0x04};
        std::vector<uint8_t> enc = box.encrypt(data);
        REQUIRE(enc == abox.encrypt(data));
        REQUIRE(box.decrypt(enc) == abox.decrypt(enc));
    }
    SECTION("a lot") {
        std::vector<uint8_t> data;
        data.resize(1024 * 1024);
        std::iota(data.begin(), data.end(), 0);
        std::vector<uint8_t> enc = box.encrypt(data);
        REQUIRE(enc == abox.encrypt(data));
        REQUIRE(box.decrypt(enc) == abox.decrypt(enc));
    }
}

TEST_CASE("SeqBox multiple") {
    std::array<uint8_t, 32> K;
    std::for_each(K.begin(), K.end(), [](uint8_t x){ return x * x + 1; });
    SeqBox box = {new IdBox, new MACBox{K}, new AESBox{K}};
    AESBox abox{K};
    MACBox mbox{K};

    SECTION("empty") {
        std::vector<uint8_t> data = {};
        std::vector<uint8_t> enc = box.encrypt(data);
        REQUIRE(enc == abox.encrypt(mbox.encrypt(data)));
        REQUIRE(box.decrypt(enc) == mbox.decrypt(abox.decrypt(enc)));
    }
    SECTION("some") {
        std::vector<uint8_t> data = {'T', 'e', 's', 't', ' ', 0x00, 0x01, 0x02, 0x03, 0x04};
        std::vector<uint8_t> enc = box.encrypt(data);
        REQUIRE(enc == abox.encrypt(mbox.encrypt(data)));
        REQUIRE(box.decrypt(enc) == mbox.decrypt(abox.decrypt(enc)));
    }
    SECTION("a lot") {
        std::vector<uint8_t> data;
        data.resize(1024 * 1024);
        std::iota(data.begin(), data.end(), 0);
        std::vector<uint8_t> enc = box.encrypt(data);
        REQUIRE(enc == abox.encrypt(mbox.encrypt(data)));
        REQUIRE(box.decrypt(enc) == mbox.decrypt(abox.decrypt(enc)));
    }
}


TEST_CASE("DRBox1", "smaller functions") {
    std::array<uint8_t, 32> root;
    cry::ECKey akey;
    cry::ECKey bkey;
    akey.gen_pub_key();
    bkey.gen_pub_key();

    DRBox a{root, bkey.get_bin_q()};
    DRBox b{root, bkey};

    SECTION("Constructor") {
        CHECK(a.pubkey == bkey.get_bin_q());
        CHECK(b.RK == root);
        CHECK(b.DHs == bkey);
        CHECK(a.RK != b.RK);              
    }

    SECTION("KDF and DHratchet") {
        auto [newkey, deckey] = a.kdf_CK(root);
        CHECK(newkey != deckey);
        CHECK(newkey != root);
    
        b.DHRatchet(a.DHs.get_bin_q());
        CHECK(b.PN == 0);
        CHECK(b.CKr == a.CKs);
        CHECK(a.DHs.get_bin_q() == b.pubkey);
        CHECK(!(b.DHs == bkey));
        CHECK(a.RK != b.RK);
    
        b.DHRatchet(a.DHs.get_bin_q());
        CHECK(b.CKr != a.CKs);
        CHECK(a.DHs.get_bin_q() == b.pubkey);
    }

    SECTION("DHRatchet more times") {
        b.DHRatchet(a.DHs.get_bin_q());
        CHECK(b.PN == 0);
        CHECK(b.CKr == a.CKs);
        CHECK(a.DHs.get_bin_q() == b.pubkey);
        CHECK(!(b.DHs == bkey));
        CHECK(a.RK != b.RK);

        a.DHRatchet(b.DHs.get_bin_q());
        CHECK(a.CKr == b.CKs);
        b.DHRatchet(a.DHs.get_bin_q());
        CHECK(b.CKr == a.CKs);
        a.DHRatchet(b.DHs.get_bin_q());
        CHECK(a.CKr == b.CKs);
        b.DHRatchet(a.DHs.get_bin_q());
        CHECK(b.CKr == a.CKs);
    }

    SECTION("create and parse header") {
        std::vector<uint8_t> msg = a.create_header(root,0,0);
        auto [key, PN, N] = a.parse_header(msg);
        CHECK(key == root);
        CHECK(PN == 0);
        CHECK(N == 0);
        
        uint16_t pn2 = 37;
        uint16_t n2 = 17;
        msg = a.create_header(root,pn2,n2);
        auto [key1, PN1, N1] = a.parse_header(msg);
        CHECK(key1 == root);
        CHECK(PN1 == pn2);
        CHECK(N1 == n2);
    }

    SECTION("Compute skipped") {
        CHECK(a.SKIPPED.size() == 0);
        CHECK(a.Nr == 0);
        a.compute_skipped(5);
        CHECK(a.SKIPPED.size() == 4);
        CHECK(a.Nr == 4);
    }
}


TEST_CASE("DRBox2","encrypt and decrypt"){
    std::array<uint8_t, 32> root;
    cry::ECKey akey;
    akey.gen_pub_key();
    cry::ECKey bkey;
    bkey.gen_pub_key();
    
    DRBox a{root, bkey.get_bin_q()};
    DRBox b{root, bkey};

    SECTION("empty") {
        std::vector<uint8_t> data = {};
        REQUIRE(b.decrypt(a.encrypt(data)) == data);
        REQUIRE(a.decrypt(b.encrypt(data)) == data);
        REQUIRE(a.decrypt(b.encrypt(data)) == data);
        REQUIRE(b.decrypt(a.encrypt(data)) == data);

        REQUIRE(a.RK != b.RK);
        REQUIRE_THROWS(a.decrypt(a.encrypt(a.encrypt(data))));
    }

    SECTION("some") {
        std::vector<uint8_t> data = {'T', 'e', 's', 't', ' ', 0x00, 0x01, 0x02, 0x03, 0x04};
        REQUIRE(b.decrypt(a.encrypt(data)) == data);
        REQUIRE(a.decrypt(b.encrypt(data)) == data);
        REQUIRE(a.decrypt(b.encrypt(data)) == data);
        REQUIRE(b.decrypt(a.encrypt(data)) == data);

        REQUIRE(a.RK != b.RK);
        REQUIRE_THROWS(a.decrypt(a.encrypt(a.encrypt(data))));
    }

    SECTION("a lot") {
        std::vector<uint8_t> data;
        data.resize(1024 * 1024);
        std::iota(data.begin(), data.end(), 0);
        REQUIRE(b.decrypt(a.encrypt(data)) == data);
        REQUIRE(a.decrypt(b.encrypt(data)) == data);
        REQUIRE(a.decrypt(b.encrypt(data)) == data);
        REQUIRE(b.decrypt(a.encrypt(data)) == data);

        REQUIRE(a.RK != b.RK);
        REQUIRE_THROWS(a.decrypt(a.encrypt(a.encrypt(data))));
    }

    SECTION("Some skipped") {
        std::vector<uint8_t> data = {'T', 'e', 's', 't', ' ', 0x00, 0x01, 0x02, 0x03, 0x04};
        REQUIRE(b.decrypt(a.encrypt(data)) == data);

        CHECK(a.CKs == b.CKr);

        std::vector skipped1 = a.encrypt(data);
        std::array<uint8_t,32> key = cry::hash_sha(a.CKs);
        std::array<uint8_t,32> pubkey = a.DHs.get_bin_q();
        CHECK(pubkey == b.pubkey); 
        CHECK(a.CKs != b.CKr);

        REQUIRE(a.decrypt(b.encrypt(data)) == data);
        REQUIRE(a.decrypt(b.encrypt(data)) == data);
        CHECK(a.CKr == b.CKs);
        REQUIRE(b.decrypt(a.encrypt(data)) == data);
        CHECK(b.CKr == a.CKs);
        REQUIRE(b.decrypt(a.encrypt(data)) == data);
        CHECK(a.PN == 2);
        CHECK(b.PN == 2);
        REQUIRE(b.SKIPPED.size() == 1);
        REQUIRE(b.decrypt(a.encrypt(data)) == data);

        REQUIRE((b.SKIPPED.find(std::make_pair(pubkey,2)) != b.SKIPPED.end()));
        REQUIRE(b.SKIPPED.find(std::make_pair(pubkey,2))->second == key);
        REQUIRE(b.decrypt(skipped1) == data);
        REQUIRE((b.SKIPPED.find(std::make_pair(pubkey,2)) == b.SKIPPED.end()));
        REQUIRE(a.decrypt(b.encrypt(data)) == data);

        std::vector<uint8_t> skippa = a.encrypt(data);
        CHECK(a.CKs != b.CKr);
        std::vector<uint8_t> skippb = b.encrypt(data);

        REQUIRE(a.decrypt(b.encrypt(data)) == data);
        CHECK(a.CKr == b.CKs);
        REQUIRE(a.decrypt(b.encrypt(data)) == data);
        CHECK(a.CKr == b.CKs);
        REQUIRE(b.decrypt(a.encrypt(data)) == data);
        REQUIRE(b.decrypt(skippa) == data);
        REQUIRE(a.decrypt(skippb) == data);
    }
}

TEST_CASE("DRBox serialize/deserialize") {
    std::array<uint8_t, 32> root;
    cry::ECKey akey;
    akey.gen_pub_key();
    cry::ECKey bkey;
    bkey.gen_pub_key();

    DRBox a{root, bkey.get_bin_q()};
    DRBox b{root, bkey};

    REQUIRE(a.serialize() == a.serialize());
    REQUIRE(b.serialize() == b.serialize());
    REQUIRE(a.serialize() != b.serialize());

    DRBox restored_a{a.serialize()};
    REQUIRE(restored_a.RK == a.RK);
    REQUIRE(restored_a.CKs == a.CKs);
    REQUIRE(restored_a.CKr == a.CKr);
    REQUIRE(restored_a.DHs == a.DHs);
    REQUIRE(restored_a.Ns == a.Ns);
    REQUIRE(restored_a.Nr == a.Nr);
    REQUIRE(restored_a.PN == a.PN);
    REQUIRE(restored_a.pubkey_to_send == a.pubkey_to_send);
    REQUIRE(restored_a.pubkey == a.pubkey);
    REQUIRE(restored_a.SKIPPED == a.SKIPPED);
}

TEST_CASE("DRBox MAC") {
    std::array<uint8_t, 32> root;
    cry::ECKey akey;
    akey.gen_pub_key();
    cry::ECKey bkey;
    bkey.gen_pub_key();

    DRBox a{root, bkey.get_bin_q()};
    DRBox b{root, bkey};

    std::vector<uint8_t> data = {'T', 'e', 's', 't', ' ', 0x00, 0x01, 0x02, 0x03, 0x04};
    auto aencrypted = a.encrypt(data);
    aencrypted[0] ^= 1 << 4;
    REQUIRE_THROWS(b.decrypt(aencrypted));
    auto bencrypted = b.encrypt(data);
    bencrypted[0] ^= 1 << 4;
    REQUIRE_THROWS(a.decrypt(bencrypted));
}
