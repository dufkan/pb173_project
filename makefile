CXXSTD=17
CXXFLAGS=-Wall -Wextra -g -DASIO_STANDALONE
LINK=libs/mbedtls/library/libmbedcrypto.a -lpthread -lstdc++fs
INCLUDE_DIRS=-Ilibs/mbedtls/include/ -Ilibs/asio/include/

CXXOPTS=-std=c++$(CXXSTD) $(CXXFLAGS) $(INCLUDE_DIRS)

TEST_JUNK=noread nowrite noexist keys/u*

all: mbedtls smain cmain tests

test: tests
	mkdir keys
	rm -f $(TEST_JUNK)
	touch noread nowrite
	chmod -r noread
	chmod -w nowrite
	./tests

cmain: client/main.cpp client/client.hpp
	$(CXX) $(CXXOPTS) -o $@ $< $(LINK)

smain: server/main.cpp server/server.hpp
	$(CXX) $(CXXOPTS) -o $@ $< $(LINK)

tests: test/test.cpp test/test_crypto.cpp test/test_server.cpp test/test_messages.cpp test/test_channel.cpp
	$(CXX) -DTESTMODE $(CXXOPTS) -o $@ $< $(LINK)

mbedtls-clean:
	cd libs/mbedtls && $(MAKE) clean

mbedtls:
	cd libs/mbedtls && $(MAKE) lib

project-clean:
	rm -rf $(TEST_JUNK) cmain smain tests

clean: mbedtls-clean project-clean
