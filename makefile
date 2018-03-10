CXXSTD=14
CXXFLAGS=-Wall -Wextra
LINK=libs/mbedtls/library/libmbedcrypto.a
INCLUDE_DIRS=-Ilibs/mbedtls/include/
SOURCES_GEN=server/impl.cpp
SOURCES_SERVER=$(SOURCES_GEN) server/main.cpp
SOURCES_CLIENT=$(SOURCES_GEN) client/main.cpp
SOURCES_TEST=$(SOURCES_GEN) test/tests.cpp

CXXOPTS=-std=c++$(CXXSTD) $(CXXFLAGS) $(INCLUDE_DIRS)
OBJECTS_SERVER=$(SOURCES_SERVER:.cpp=.o)
OBJECTS_CLIENT=$(SOURCES_CLIENT:.cpp=.o)
OBJECTS_TEST=$(SOURCES_TEST:.cpp=.o)

all: mbedtls server-main client-main tests

test: tests
	rm -f noread nowrite noexist
	touch noread nowrite
	chmod -r noread
	chmod -w nowrite
	./tests

client-main: $(OBJECTS_CLIENT)
	$(CXX) $(CXXOPTS) -o $@ $^ $(LINK)

server-main: $(OBJECTS_SERVER)
	$(CXX) $(CXXOPTS) -o $@ $^ $(LINK)

tests: $(OBJECTS_TEST)
	$(CXX) $(CXXOPTS) -o $@ $^ $(LINK)

%.o: %.cpp
	$(CXX) -c $(CXXOPTS) -o $@ $<

clean:
	rm -rf $(OBJECTS_SERVER) $(OBJECTS_CLIENT) $(OBJECTS_TEST)

mbedtls:
	cd libs/mbedtls && make lib
