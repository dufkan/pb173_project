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
