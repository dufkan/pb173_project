#include "impl.hpp"

void print_help(const std::string& program) {
    std::cout << "Usage: " << program << " {D|E} filename key" << std::endl;
}

int main(int argc, char** argv) {
    if(argc < 4) {
        print_help(argv[0]);
        return 1;
    }

    char mode = argv[1][0];
    std::string fname = argv[2];
    std::array<uint8_t, 16> iv{};
    std::array<uint8_t, 16> key = parse_key(argv[3]);

    if(mode == 'E') {
        encrypt_file(fname, fname + ".enc", iv, key);
    } else if(mode == 'D') {
        decrypt_file(fname + ".enc", fname, iv, key);
    } else {
        print_help(argv[0]);
        return 2;
    }

    return 0;
}
