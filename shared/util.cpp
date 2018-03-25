#include "util.hpp"

std::vector<uint8_t> util::read_file(const std::string& fname) {
    std::ifstream ifs{fname, std::ios::binary};
    if(!ifs.is_open())
        throw std::ios_base::failure{"File " + fname + " couldn't be opened for reading."};
    ifs >> std::noskipws;
    return std::vector<uint8_t>{std::istream_iterator<uint8_t>{ifs}, std::istream_iterator<uint8_t>{}};
}

void util::write_file(const std::string& fname, const std::vector<uint8_t>& data, bool append) {
    std::ofstream ofs{fname, std::ios::binary | (append ? std::ios::app : std::ios::trunc)};
    if(!ofs.is_open())
        throw std::ios_base::failure{"File " + fname + "couldn't be opened for writing."};
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
}

