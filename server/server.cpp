#include "server.hpp"

bool add_user(std::string pseudonym, std::vector<uint8_t> pubkey) {
    std::ifstream ifs{pseudonym};
    if(ifs.good())
        return false;

    ifs.close();

    util::write_file(pseudonym, pubkey);
    return true;
}

std::vector<uint8_t> get_user(std::string pseudonym) {
    return util::read_file(pseudonym);
}

bool remove_user(std::string pseudonym) {
    return !std::remove(pseudonym.c_str());
}

#if 0
std::pair<std::string, Channel> handle_connection(/* connection */) {
    auto msg = recv();
    // get challenge and msg_content
    auto rc = cry::decryptRSA(challenge, privkey);
    auto plain = cry::decryptAES(msg_content, rc);
    // get pseudo from plain
    // get pubkey if it is in plain or lookup in db
    if (!pubkey)
        throw "Bad";
    auto [challmsg, chall] = create_challenge(pubkey);
    send(challmsg);
    auto resp = recv();
    auto cry::decryptAES(resp, hash(chall + rc))
    
}
#endif
