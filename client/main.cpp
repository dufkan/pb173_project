#include "client.hpp"
#include "asio.hpp"
#include <iostream>

int main(int argc, char** argv) {
    Client c = argc == 2 ? Client{argv[1]} : Client{};
    c.run();
    return 0;
}
