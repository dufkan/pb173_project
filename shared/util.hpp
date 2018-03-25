#ifndef UTIL_HPP
#define UTIL_HPP

#include <string>
#include <vector>
#include <fstream>
#include <iterator>

namespace util {
/**
 * Read contents of file.
 *
 * @param fname Name of file to read from
 * @return File contents
 */
std::vector<uint8_t> read_file(const std::string& fname) {
    std::ifstream ifs{fname, std::ios::binary};
    if(!ifs.is_open())
        throw std::ios_base::failure{"File " + fname + " couldn't be opened for reading."};
    ifs >> std::noskipws;
    return std::vector<uint8_t>{std::istream_iterator<uint8_t>{ifs}, std::istream_iterator<uint8_t>{}};
}


/**
 * Write vector of bytes into file.
 *
 * @param fname Name of file to write to
 * @param data Bytes to write
 */
void write_file(const std::string& fname, const std::vector<uint8_t>& data, bool append = true) {
    std::ofstream ofs{fname, std::ios::binary | (append ? std::ios::app : std::ios::trunc)};
    if(!ofs.is_open())
        throw std::ios_base::failure{"File " + fname + "couldn't be opened for writing."};
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
}


} // namespace util
#endif
