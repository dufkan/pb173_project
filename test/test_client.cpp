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


TEST_CASE("X3DH secret share client") {
    Client alice;
    Client bob;
    uint8_t id = bob.generate_prekey();
    uint8_t id2 = bob.generate_prekey();
    CHECK(bob.prekeys.find(id) != bob.prekeys.end());
    CHECK(bob.prekeys.find(id2) != bob.prekeys.end());
    cry::ECKey& OPK = bob.prekeys[id];
    cry::ECKey& EK = bob.prekeys[id2];

    auto SPKb = bob.SPKey.get_bin_q();
    auto IKb = bob.IKey.get_bin_q();
    auto OPKb = OPK.get_bin_q();
    std::array<uint8_t, 32> Ka = alice.compute_share_init(EK, SPKb, IKb, OPKb);

    auto IKa = alice.IKey.get_bin_q();
    auto EKa = EK.get_bin_q();
    std::array<uint8_t, 32> Kb = bob.compute_share_recv(IKa, EKa, id);

    CHECK(Ka == Kb);
    
}





TEST_CASE("X3DH message, prekeys exchange, initial message and share secret key") {
    Client alice;
    Client bob;
    
    uint16_t id = bob.generate_prekey();
    cry::ECKey& OPK = bob.prekeys[id];
    CHECK(bob.prekeys.find(id) != bob.prekeys.end());
    msg::RetPrekey msg_pre{"bob", id, OPK.get_bin_q(), bob.IKey.get_bin_q(), bob.SPKey.get_bin_q()};

    std::string text = "Ahoj ja jsem alice.";
    
    std::vector<uint8_t> msg_ser = alice.x3dh_msg_byte("bob",msg_pre,text); 

    std::unique_ptr<msg::Message> deserialized = msg::X3dhInit::deserialize(msg_ser);
    msg::X3dhInit& restored = dynamic_cast<msg::X3dhInit&>(*deserialized.get());
    
    CHECK(restored.get_name() == "bob");
    CHECK(restored.get_id() == id);
    CHECK(restored.get_IK() == alice.IKey.get_bin_q());
    /*
    std::vector<uint8_t> text_u(text.begin(), text.end());
    auto text_enc = cry::encrypt_aes(text_u, {}, alice.contacts["bob"]);
    CHECK(restored.get_text() == text_enc);
       
    auto IK = restored.get_IK();
    auto EK = restored.get_EK();
    auto K = bob.compute_share_recv(IK, EK, restored.get_id());
    
    CHECK(alice.contacts["bob"] == K);
    
    bob.contacts[restored.get_name()]=K;

    auto text_dec = cry::decrypt_aes(restored.get_text(), {}, K);
    CHECK(text_dec == text_u);
    std::cout << text_dec.size();

    std::vector<char> text_v(text_dec.begin(), text_dec.end());
    std::string text_s(text_dec.begin(), text_dec.end());
    std::cout << text_s.size() <<std::endl << text_s << std::endl;
     */
    auto recv = bob.handle_x3dh_msg(msg_ser); 

    CHECK(bob.contacts["bob"] == alice.contacts["bob"]);
    CHECK(recv.second == text);
}
