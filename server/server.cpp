#include "server.hpp"

std::vector<uint8_t> read_file(const std::string& fname) {
    std::ifstream ifs{fname, std::ios::binary};
    if(!ifs.is_open())
        throw std::ios_base::failure{"File " + fname + " couldn't be opened for reading."};
    ifs >> std::noskipws;
    return std::vector<uint8_t>{std::istream_iterator<uint8_t>{ifs}, std::istream_iterator<uint8_t>{}};
}

void write_file(const std::string& fname, const std::vector<uint8_t>& data, bool append) {
    std::ofstream ofs{fname, std::ios::binary | (append ? std::ios::app : std::ios::trunc)};
    if(!ofs.is_open())
        throw std::ios_base::failure{"File " + fname + "couldn't be opened for writing."};
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
}

bool add_user(std::string pseudonym, std::vector<uint8_t> pubkey) {
    std::ifstream ifs{pseudonym};
    if(ifs.good())
        return false;

    ifs.close();

    write_file(pseudonym, pubkey);
    return true;
}

std::vector<uint8_t> get_user(std::string pseudonym) {
    return read_file(pseudonym);
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
