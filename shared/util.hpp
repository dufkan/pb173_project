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
std::vector<uint8_t> read_file(const std::string& fname);

/**
 * Write vector of bytes into file.
 *
 * @param fname Name of file to write to
 * @param data Bytes to write
 */
void write_file(const std::string& fname, const std::vector<uint8_t>& data, bool append = false);

} // namespace util
#endif
