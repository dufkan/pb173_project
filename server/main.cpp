#include "server.hpp"
#include <iostream>

void print_help(const std::string& program) {
    std::cout << "Usage: " << program << " ... " << std::endl;
}

int main(int argc, char** argv) {
    print_help(argv[0]);
    return 0;
}
