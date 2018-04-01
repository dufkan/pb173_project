#include "../shared/messages.hpp"

TEST_CASE("Message Register","(de)serialize") {
    std::vector<uint8_t> key = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
    std::string name = "some pseudonym";
    auto client = std::make_unique<msg::Register>(name,key);
    std::vector<uint8_t> data = client->serialize();
    auto client_deser = client->deserialize(data);
    std::unique_ptr<msg::Register> klient(static_cast<msg::Register*>(client_deser.release())); 

    CHECK(msg::type(data)==msg::MessageType::Register);
    CHECK(klient->get_name()==name);
    CHECK(((*client)==(*klient)));
}


TEST_CASE("Message Send", "(de)serialize") {
    std::string name = "some pseudonym";
    std::vector<uint8_t> text = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
    auto send = std::make_unique<msg::Send>(name,text);
    std::vector<uint8_t> send_ser = send->serialize();
    auto send_deser = send->deserialize(send_ser);
    std::unique_ptr<msg::Send> send2(static_cast<msg::Send*>(send_deser.release()));

    CHECK(msg::type(send_ser)==msg::MessageType::Send);
    CHECK(send2->get_receiver()==name);
    CHECK(((*send)==(*send2)));
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
