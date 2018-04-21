#include <sstream>

TEST_CASE("Connection") {
    Server s;
    auto st = std::thread{[&](){
        s.run();
    }};
    std::this_thread::sleep_for(std::chrono::seconds{10}); // let the server start first

    SECTION("single client") {
        std::istringstream cin;
        std::ostringstream cout;
        std::ostringstream cerr;
        cin.str("q\n");
        Client c{"C", cin, cout, cerr};
        auto ct = std::thread{[&](){
            c.run();
        }};
        ct.join();
        REQUIRE(cout.str().find("I am in!") != std::string::npos);
    }

    SECTION("multiple clients") {
        const int CLIENT_NUM = 10;
        std::vector<std::unique_ptr<Client>> clients;
        std::vector<std::thread> threads;
        std::vector<std::tuple<std::istringstream, std::ostringstream, std::ostringstream>> streams;
        clients.reserve(CLIENT_NUM);
        threads.reserve(CLIENT_NUM);
        streams.resize(10);
        for(int i = 0; i < CLIENT_NUM; ++i) {
            auto& [cin, cout, cerr] = streams[i];
            cin.str("q\n");
            clients.emplace_back(std::unique_ptr<Client>(new Client{"C" + std::to_string(i), cin, cout, cerr}));
            auto& c = *(clients.back());
            threads.emplace_back(std::thread{[&](){
                c.run();
            }});
        }
        for(int i = 0; i < CLIENT_NUM; ++i) {
            threads[i].join();
            REQUIRE(std::get<1>(streams[i]).str().find("I am in!") != std::string::npos);
        }
    }

    s.shutdown = true;
    st.join();
}

