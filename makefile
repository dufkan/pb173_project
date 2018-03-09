CXXSTD=14
CXXFLAGS=-Wall -Wextra
LINK=-lmbedcrypto
SOURCES_GEN=src/impl.cpp
SOURCES_MAIN=$(SOURCES_GEN) src/server/main.cpp
SOURCES_TEST=$(SOURCES_GEN) test/tests.cpp

CXXOPTS=-std=c++$(CXXSTD) $(CXXFLAGS)
OBJECTS_MAIN=$(SOURCES_MAIN:.cpp=.o)
OBJECTS_TEST=$(SOURCES_TEST:.cpp=.o)

all: main main-test

test: main-test
	rm -f noread nowrite noexist
	touch noread nowrite
	chmod -r noread
	chmod -w nowrite
	./main-test

main: $(OBJECTS_MAIN)
	$(CXX) $(CXXOPTS) -o $@ $^ $(LINK)

main-test: $(OBJECTS_TEST)
	$(CXX) $(CXXOPTS) -o $@ $^ $(LINK)

%.o: %.cpp
	$(CXX) -c $(CXXOPTS) -o $@ $<

clean:
	rm -rf $(OBJECTS_MAIN) $(OBJECTS_TEST)
