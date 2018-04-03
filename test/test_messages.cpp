#include "../shared/messages.hpp"

TEST_CASE("Message Register","(de)serialize") {
    std::vector<uint8_t> key = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
    std::string name = "some pseudonym";
    auto client = msg::Register{name,key};

    CHECK(key == client.get_key());
    CHECK(name == client.get_name());

    std::vector<uint8_t> data = client.serialize();
    CHECK(msg::type(data) == msg::MessageType::Register);

    std::unique_ptr<msg::Message> msg_des = msg::Register::deserialize(data); 
    msg::Register& reg_des = dynamic_cast<msg::Register&>(*msg_des.get());
    CHECK(reg_des == client);
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
