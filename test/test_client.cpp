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

/*
    SECTION("O neco ladneji"){
        std::string text2 = "Ahoj, tohle je testovaci zprava, tak snad dorazi v poradku";
        auto msg_send = cl.send_msg_byte(name, text2);
        auto msg_recv = cl.handle_recv_msg(msg_send);
        CHECK(name == msg_recv.first);
        CHECK(text2 == msg_recv.second);
    }
*/}


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
    SECTION("With OPK") {

    uint16_t id = bob.generate_prekey();
    CHECK(bob.prekeys.find(id) != bob.prekeys.end());
    cry::ECKey& OPK = bob.prekeys[id];
    
    uint16_t id2 = bob.generate_prekey();
    CHECK(bob.prekeys.find(id2) != bob.prekeys.end());
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

    SECTION("Without OPK") {
    
    uint16_t id2 = bob.generate_prekey();
    CHECK(bob.prekeys.find(id2) != bob.prekeys.end());
    cry::ECKey& EK = bob.prekeys[id2];
    
    auto SPKb = bob.SPKey.get_bin_q();
    auto IKb = bob.IKey.get_bin_q();
    std::array<uint8_t, 32> Ka = alice.compute_share_init(EK, SPKb, IKb, {});

    auto IKa = alice.IKey.get_bin_q();
    auto EKa = EK.get_bin_q();
    std::array<uint8_t, 32> Kb = bob.compute_share_recv(IKa, EKa, 0x01);

    CHECK(Ka == Kb);
    }
}




TEST_CASE("X3DH message, prekeys exchange, initial message and share secret key") {
    Client alice;
    Client bob;
    
    uint16_t id = bob.generate_prekey();
    cry::ECKey& OPK = bob.prekeys[id];
    CHECK(bob.prekeys.find(id) != bob.prekeys.end());
    msg::RetPrekey msg_pre{"bob", id, OPK.get_bin_q(), bob.IKey.get_bin_q(), bob.SPKey.get_bin_q()};

    std::string text = "Ahoj ja jsem alice.";
    
    std::vector<uint8_t> msg_ser = alice.x3dh_msg_byte(msg_pre,text); 

    std::unique_ptr<msg::Message> deserialized = msg::X3dhInit::deserialize(msg_ser);
    msg::X3dhInit& restored = dynamic_cast<msg::X3dhInit&>(*deserialized.get());
    
    CHECK(restored.get_name() == "bob");
    CHECK(restored.get_id() == id);
    CHECK(restored.get_IK() == alice.IKey.get_bin_q());

    auto recv = bob.handle_x3dh_msg(msg_ser); 

    CHECK(bob.prekeys.find(id) == bob.prekeys.end());
    CHECK(bob.contacts["bob"] == alice.contacts["bob"]);
    CHECK(recv.second == text);
}


TEST_CASE("save and load client params") {
    std::string pseudonym = "noone";
    std::vector<uint8_t> bin_ik;
    std::vector<uint8_t> bin_spk;
    std::array<uint8_t, 32> bin_qp;

    Client manka;
    manka.load_keys();
    manka.generate_prekey_lt('b');
    bin_ik = manka.IKey.get_key_binary();
    bin_spk = manka.SPKey.get_key_binary();
    bin_qp = manka.IKey.get_bin_q();
    uint8_t id1 = manka.generate_prekey();
    uint8_t id2 = manka.generate_prekey();
    uint8_t id3 = manka.generate_prekey();
    manka.save_keys();
 
    std::array<uint8_t, 32> key_cipis = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
    std::array<uint8_t, 32> key_raholec = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
    manka.add_contact("cipis",key_cipis);
    manka.add_contact("raholec",key_raholec);
    manka.save_contacts();
       
    Client rumc;
    rumc.load_keys();
    rumc.load_contacts();    

    CHECK(bin_ik == rumc.IKey.get_key_binary());
    CHECK(bin_spk == rumc.SPKey.get_key_binary());
    CHECK(bin_qp == rumc.IKey.get_bin_q());
    CHECK(rumc.prekeys.size() == manka.prekeys.size());
    //CHECK(rumc.prekeys.size() == 3);
    CHECK(manka.prekeys[id1] == rumc.prekeys[id1]);
    CHECK(manka.prekeys[id2] == rumc.prekeys[id2]);
    CHECK(manka.prekeys[id3] == rumc.prekeys[id3]);

    CHECK(manka.contacts == rumc.contacts);
}

TEST_CASE("Client friend_box") {
    Client alice{"Alice"};
    Client bob{"Bob"};

    auto msg_prekey = msg::RetPrekey{bob.pseudonym, 0, {}, bob.IKey.get_bin_q(), bob.SPKey.get_bin_q()};

    std::vector<uint8_t> msg = alice.x3dh_msg_byte(msg_prekey, "Ahoj");
    auto [name,text] = bob.handle_x3dh_msg(msg);
    CHECK(text == "Ahoj");
    CHECK(bob.friend_box.size() == 1);
    CHECK(alice.friend_box.size() == 1);
}
