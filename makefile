CXXSTD=17
CXXFLAGS=-Wall -Wextra -DASIO_STANDALONE
LINK=libs/mbedtls/library/libmbedcrypto.a -lpthread
INCLUDE_DIRS=-Ilibs/mbedtls/include/ -Ilibs/asio/include/

CXXOPTS=-std=c++$(CXXSTD) $(CXXFLAGS) $(INCLUDE_DIRS)

TEST_JUNK=noread nowrite noexist u*

all: mbedtls smain cmain tests

test: tests
	rm -f $(TEST_JUNK)
	touch noread nowrite
	chmod -r noread
	chmod -w nowrite
	./tests

cmain: client/main.cpp
	$(CXX) $(CXXOPTS) -o $@ $^ $(LINK)

smain: server/main.cpp
	$(CXX) $(CXXOPTS) -o $@ $^ $(LINK)

tests: test/test.cpp
	$(CXX) -DTESTMODE $(CXXOPTS) -o $@ $^ $(LINK)

clean:
	rm -rf $(TEST_JUNK) cmain smain tests

mbedtls:
	cd libs/mbedtls && $(MAKE) lib
