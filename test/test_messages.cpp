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

    CHECK(original == restored);
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
