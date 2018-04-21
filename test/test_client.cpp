#include "../client/client.hpp"

TEST_CASE("Create and encrypt message","create_message"){
    Client cl;

    std::array<uint8_t, 32> key = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
    std::string name = "friend";
    cl.add_contact(name,key);

    CHECK(cl.get_key(name)==key);
    
    std::vector<uint8_t> text = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    msg::Send msg_send = cl.create_message(name, key,text);
    std::vector<uint8_t> dec_text = cry::decrypt_aes(msg_send.get_text(),{},key);

    CHECK(dec_text==text);

}


TEST_CASE("Create and recieve message","without network") {
    Client cl;
    std::array<uint8_t, 32> key = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
    std::string name = "friend";
    cl.add_contact(name,key);
    
    SECTION("Trochu kostrbate") {
        std::string text = "Ahoj";
        std::vector<uint8_t> text_u(text.begin(), text.end());
        msg::Send msg_send = cl.create_message(name, key, text_u);
    
        std::pair<std::string,std::string> recv = cl.handle_recv_msg(msg_send.serialize());
        CHECK(recv.first == name);
        CHECK(recv.second == text);
    }


    SECTION("O neco ladneji"){
        std::string text2 = "Ahoj, tohle je testovaci zprava, tak snad dorazi v poradku";
        auto msg_send = cl.send_msg_byte(name, text2);
        auto msg_recv = cl.handle_recv_msg(msg_send);
        CHECK(name == msg_recv.first);
        CHECK(text2 == msg_recv.second);
    }
}

TEST_CASE("Generate prekey") {
    Client c;
    size_t init = c.prekeys.size();

    SECTION("Single key") {
        c.generate_prekey();
        REQUIRE(c.prekeys.size() == init + 1);
    }

    SECTION("Multiple keys") {
        for(int i = 0; i < 32; ++i)
            c.generate_prekey();
        REQUIRE(c.prekeys.size() == init + 32);
    }
}

/*
TEST_CASE("Create message","Interaction with user"){
    


}*/
