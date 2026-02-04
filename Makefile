CXX = g++
CXXFLAGS = -std=c++17 -O2 -DUNICODE -D_UNICODE -Wall -I./src
LDFLAGS = -lcurl -lsqlite3 -lole32 -loleaut32 -lwbemuuid -lbcrypt

SRC = $(wildcard src/*.cpp)
OBJ = $(SRC:.cpp=.o)

all: dlp_agent.exe

dlp_agent.exe: $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $@ $(LDFLAGS)

clean:
	rm -f dlp_agent.exe src/*.o
