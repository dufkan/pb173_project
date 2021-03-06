#include "../shared/messages.hpp"

TEST_CASE("Message ClientInit") {
    std::array<uint8_t, 32> Rc;
    cry::random_data(Rc);
    std::vector<uint8_t> key = CLIENT_KEY.export_pub();
    std::string pseudonym = "some pseudonym";
    auto original = msg::ClientInit{pseudonym, Rc, key};

    CHECK(original.Rc == Rc);
    CHECK(original.pseudonym == pseudonym);
    CHECK(original.key == key);

    CHECK(original.eRc.empty());
    CHECK(original.epayload.empty());
    original.encrypt(SERVER_KEY);
    CHECK(!original.eRc.empty());
    CHECK(!original.epayload.empty());

    std::vector<uint8_t> serialized = original.serialize();
    CHECK(msg::type(serialized) == msg::MessageType::ClientInit);

    std::unique_ptr<msg::Message> deserialized = msg::ClientInit::deserialize(serialized);
    msg::ClientInit& restored = dynamic_cast<msg::ClientInit&>(*deserialized.get());

    CHECK(restored.key.empty());
    CHECK(restored.pseudonym.empty());
    restored.decrypt(SERVER_KEY);
    CHECK(restored.key == key);
    CHECK(restored.pseudonym == pseudonym);
    CHECK(restored.Rc == Rc);
    CHECK(restored.check_mac());
    CHECK(original == restored);
}

TEST_CASE("Message ServerResp") {
    std::array<uint8_t, 32> Rc;
    cry::random_data(Rc);
    std::array<uint8_t, 32> Rs;
    cry::random_data(Rs);

    auto original = msg::ServerResp{Rs, Rc};

    CHECK(original.Rs == Rs);
    CHECK(original.Rc == Rc);

    original.encrypt(CLIENT_KEY);

    std::vector<uint8_t> serialized = original.serialize();
    CHECK(msg::type(serialized) == msg::MessageType::ServerResp);

    std::unique_ptr<msg::Message> deserialized = msg::ServerResp::deserialize(serialized);
    msg::ServerResp& restored = dynamic_cast<msg::ServerResp&>(*deserialized.get());

    restored.decrypt(CLIENT_KEY);
    CHECK(restored.Rs == Rs);
    CHECK(restored.Rc == Rc);

    CHECK(original == restored);
}

TEST_CASE("Message ClientResp") {
    std::array<uint8_t, 32> Rs;
    cry::random_data(Rs);
    std::array<uint8_t, 32> K;

    SECTION ("Small") {
        auto original = msg::ClientResp{Rs};

        CHECK(original.Rs == Rs);
        original.encrypt(K);

        std::vector<uint8_t> serialized = original.serialize();
        CHECK(msg::type(serialized) == msg::MessageType::ClientResp);

        std::unique_ptr<msg::Message> deserialized = msg::ClientResp::deserialize(serialized);
        msg::ClientResp& restored = dynamic_cast<msg::ClientResp&>(*deserialized.get());

        restored.decrypt(K);
        CHECK(restored.Rs == Rs);
        CHECK(original == restored);
    }
    SECTION("With keys") {
        std::array<uint8_t, 32> IK;
        cry::random_data(IK);
        std::array<uint8_t, 32> SPK;
        cry::random_data(SPK);
        cry::RSAKey rsak;
        cry::generate_rsa_keys(rsak,rsak);
        std::vector<uint8_t> rsak_exp = rsak.export_pub();    
        std::array<uint8_t, 512> sign = cry::rsa_sign(rsak,SPK);

        auto original = msg::ClientResp{Rs,IK,SPK,sign,rsak_exp};
        original.encrypt(K);
        CHECK(original.Rs == Rs);
        CHECK(original.IK == IK);
        CHECK(original.SPK == SPK);
        CHECK(original.sign == sign);
        CHECK(original.rsak == rsak_exp);
        
        std::vector<uint8_t> serialized = original.serialize();
        CHECK(msg::type(serialized) == msg::MessageType::ClientResp);
        
        std::unique_ptr<msg::Message> deserialized = msg::ClientResp::deserialize(serialized);
        msg::ClientResp& restored = dynamic_cast<msg::ClientResp&>(*deserialized.get());
        
        restored.decrypt(K);
        CHECK(restored.Rs == Rs);
        CHECK(restored.IK == IK);
        CHECK(restored.SPK == SPK);
        CHECK(restored.sign == sign);
        CHECK(restored.rsak == rsak_exp);
        
        cry::RSAKey rsak2;
        auto [rsign, key] = restored.get_sign_and_key();
        rsak2.import(*key);
        REQUIRE(rsak2.has_pub());
        CHECK(cry::rsa_verify(rsak2,SPK,*rsign));
    }
}


TEST_CASE("Message Send", "(de)serialize") {
    std::string name = "some pseudonym";
    std::vector<uint8_t> text = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
    auto send = msg::Send{name,text};

    CHECK(text == send.get_text());
    CHECK(name == send.get_receiver());

    std::vector<uint8_t> send_ser = send.serialize();
    CHECK(msg::type(send_ser) == msg::MessageType::Send);
    
    std::unique_ptr<msg::Message> msg_des = msg::Send::deserialize(send_ser);
    msg::Send& send_des = dynamic_cast<msg::Send&>(*msg_des.get());

    CHECK(send_des == send);
}

TEST_CASE("Message Recv") {
    std::string name = "some pseudonym";
    std::vector<uint8_t> text = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    auto recv = msg::Recv{name,text};

    REQUIRE(text == recv.get_text());
    REQUIRE(name == recv.get_sender());

    std::vector<uint8_t> recv_ser = recv.serialize();

    REQUIRE(msg::type(recv_ser) == msg::MessageType::Recv);

    std::unique_ptr<msg::Message> msg_des = msg::Recv::deserialize(recv_ser);
    msg::Recv& recv_des = dynamic_cast<msg::Recv&>(*msg_des.get());

    CHECK(recv_des == recv);
}

TEST_CASE("Message RetOline") {
    std::set<std::string> online;
    online.insert("Anna");
    online.insert("Alice");
    online.insert("Bob");

    auto reto = msg::RetOnline(online);
    REQUIRE((reto.get_users()) == online);
    REQUIRE(reto.is_online("Anna"));
    REQUIRE(reto.is_online("Alice"));
    REQUIRE(reto.is_online("Bob"));
    REQUIRE(!reto.is_online("Martin"));

    std::vector<uint8_t> reto_ser = reto.serialize();

    REQUIRE(msg::type(reto_ser) == msg::MessageType::RetOnline);

    std::unique_ptr<msg::Message> msg_reto = reto.deserialize(reto_ser);
    msg::RetOnline& reto_des = dynamic_cast<msg::RetOnline&>(*msg_reto.get());

    CHECK(reto == reto_des);
}

TEST_CASE("Message ReqPrekey") {
    auto original = msg::ReqPrekey{};

    std::vector<uint8_t> serialized = original.serialize();
    CHECK(msg::type(serialized) == msg::MessageType::ReqPrekey);

    std::unique_ptr<msg::Message> deserialized = msg::ReqPrekey::deserialize(serialized);
    msg::ReqPrekey& restored = dynamic_cast<msg::ReqPrekey&>(*deserialized.get());

    CHECK(original == restored);
}

TEST_CASE("Message AskPrekey") {
    std::string pseudonym = "House";

    auto original = msg::AskPrekey{pseudonym};

    CHECK(original.pseudonym == pseudonym);

    std::vector<uint8_t> serialized = original.serialize();
    CHECK(msg::type(serialized) == msg::MessageType::AskPrekey);

    std::unique_ptr<msg::Message> deserialized = msg::AskPrekey::deserialize(serialized);
    msg::AskPrekey& restored = dynamic_cast<msg::AskPrekey&>(*deserialized.get());

    CHECK(original == restored);
}

TEST_CASE("Message UploadPrekey") {
    uint16_t id = 65535;
    std::array<uint8_t, 32> key;
    cry::random_data(key);

    auto original = msg::UploadPrekey{id, key};

    CHECK(original.id == id);
    CHECK(original.key == key);

    std::vector<uint8_t> serialized = original.serialize();
    CHECK(msg::type(serialized) == msg::MessageType::UploadPrekey);

    std::unique_ptr<msg::Message> deserialized = msg::UploadPrekey::deserialize(serialized);
    msg::UploadPrekey& restored = dynamic_cast<msg::UploadPrekey&>(*deserialized.get());

    CHECK(original == restored);
}


TEST_CASE("Message RetPrekye") {
    uint16_t id = 65535;
    std::string name = "my_name";
    std::array<uint8_t, 32> OPK;
    cry::random_data(OPK);

    std::array<uint8_t, 32> IK;
    cry::random_data(IK);

    std::array<uint8_t, 32> SPK;
    cry::random_data(SPK);

    cry::RSAKey rsak;
    cry::generate_rsa_keys(rsak,rsak);
    std::vector<uint8_t> rsak_exp = rsak.export_all();

    std::array<uint8_t,512> sign;
    cry::random_data(sign);
    
    auto original = msg::RetPrekey{name,id,OPK,IK,SPK,sign,rsak_exp};
    
    CHECK(original.pseudonym == name);
    CHECK(name == original.get_name());
    CHECK(original.id == id);
    CHECK(id == original.get_id());
    CHECK(original.IKey == IK);
    CHECK(IK == original.get_IK());
    CHECK(original.SPKey == SPK);
    CHECK(SPK == original.get_SPK());
    CHECK(original.OPKey == OPK);
    CHECK(OPK == original.get_OPK());
    CHECK(original.sign == sign);
    CHECK(sign == original.get_sign());
    CHECK(original.signing_key == rsak_exp);
    CHECK(rsak_exp == original.get_signing_key());

    std::vector<uint8_t> serialized = original.serialize();
    CHECK(msg::type(serialized) == msg::MessageType::RetPrekey);

    std::unique_ptr<msg::Message> deserialized = msg::RetPrekey::deserialize(serialized);
    msg::RetPrekey& restored = dynamic_cast<msg::RetPrekey&>(*deserialized.get());
    
    CHECK(original == restored);
}


TEST_CASE("Message X3dhInit") {
    uint16_t id = 65535;
    std::array<uint8_t, 32> IK;
    cry::random_data(IK);

    std::array<uint8_t, 32> EK;
    cry::random_data(EK);
    
    std::string pseudonym = "my_name";
    std::vector<uint8_t> text = cry::get_random_data((size_t) 47);

    auto original = msg::X3dhInit{pseudonym, IK, EK, id, text};
    
    CHECK(original.pseudonym == pseudonym);
    CHECK(original.get_name() == pseudonym);
    CHECK(original.IK == IK);
    CHECK(original.get_IK() == IK);
    CHECK(original.EK == EK);
    CHECK(original.get_EK() == EK);
    CHECK(original.id == id);
    CHECK(original.get_id() == id);
    CHECK(original.text == text);
    CHECK(original.get_text() == text);

    std::vector<uint8_t> serialized = original.serialize();
    CHECK(msg::type(serialized) == msg::MessageType::X3dhInit);
    
    std::unique_ptr<msg::Message> deserialized = msg::X3dhInit::deserialize(serialized);
    msg::X3dhInit& restored = dynamic_cast<msg::X3dhInit&>(*deserialized.get());
    
    CHECK(original == restored);
}
