CXXSTD=14
CXXFLAGS=-Wall -Wextra -DASIO_STANDALONE
LINK=libs/mbedtls/library/libmbedcrypto.a -lpthread
INCLUDE_DIRS=-Ilibs/mbedtls/include/ -Ilibs/asio/include/
SOURCES_OTHER=shared/crypto.cpp shared/util.cpp
SOURCES_SERVER=server/server.cpp $(SOURCES_OTHER)
SOURCES_CLIENT=client/client.cpp $(SOURCES_OTHER)
SOURCES_TEST=test/test_server.cpp test/test_crypto.cpp
SOURCES_TEST_ALL=$(SOURCES_SERVER) $(SOURCES_CLIENT) $(SOURCES_OTHER) $(SOURCES_TEST)

CXXOPTS=-std=c++$(CXXSTD) $(CXXFLAGS) $(INCLUDE_DIRS)
OBJECTS_SERVER=$(SOURCES_SERVER:.cpp=.o)
OBJECTS_CLIENT=$(SOURCES_CLIENT:.cpp=.o)
OBJECTS_TEST_ALL=$(SOURCES_TEST_ALL:.cpp=.o)

TEST_JUNK=noread nowrite noexist u*

all: mbedtls server-main client-main tests

test: tests
	rm -f $(TEST_JUNK)
	touch noread nowrite
	chmod -r noread
	chmod -w nowrite
	./tests

client-main: $(OBJECTS_CLIENT)
	$(CXX) $(CXXOPTS) -o $@ $^ client/main.cpp $(LINK)

server-main: $(OBJECTS_SERVER)
	$(CXX) $(CXXOPTS) -o $@ $^ server/main.cpp $(LINK)

tests: $(OBJECTS_TEST_ALL)
	$(CXX) $(CXXOPTS) -o $@ $^ $(LINK)

%.o: %.cpp
	$(CXX) -c $(CXXOPTS) -o $@ $<

clean:
	rm -rf $(OBJECTS_SERVER) $(OBJECTS_CLIENT) $(OBJECTS_TEST_ALL) $(TEST_JUNK)

mbedtls:
	cd libs/mbedtls && $(MAKE) lib
