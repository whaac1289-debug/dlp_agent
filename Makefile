CXX = g++
CXXFLAGS = -std=c++17 -O2 -DUNICODE -D_UNICODE -Wall -I./src
LDFLAGS = -lcurl -lsqlite3 -lole32 -loleaut32 -lwbemuuid -lbcrypt -lfltlib

SRC = $(shell find src -name '*.cpp')
OBJ = $(SRC:.cpp=.o)
TEST_SRC = $(shell find tests -name '*.cpp')
TEST_BINS = $(TEST_SRC:.cpp=.exe)

all: dlp_agent.exe

dlp_agent.exe: $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $@ $(LDFLAGS)

clean:
	rm -f dlp_agent.exe src/*.o tests/*.exe

tests: $(TEST_BINS)

tests/%.exe: tests/%.cpp $(SRC)
	$(CXX) $(CXXFLAGS) -DDLP_ENABLE_TESTS $^ -o $@ $(LDFLAGS)
