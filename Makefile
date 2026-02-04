CXX = g++
CXXFLAGS = -std=c++17 -O2 -DUNICODE -D_UNICODE -Wall -I./agent/src
LDFLAGS = -lcurl -lsqlite3 -lole32 -loleaut32 -lwbemuuid -lbcrypt -lfltlib

AGENT_SRC = $(shell find agent/src -name '*.cpp')
AGENT_OBJ = $(AGENT_SRC:.cpp=.o)
AGENT_TEST_SRC = $(shell find agent/tests -name '*.cpp')
AGENT_TEST_BINS = $(AGENT_TEST_SRC:.cpp=.exe)

.PHONY: agent-build server-run migrate test docker-build release clean

agent-build: dlp_agent.exe

dlp_agent.exe: $(AGENT_SRC)
	$(CXX) $(CXXFLAGS) $(AGENT_SRC) -o $@ $(LDFLAGS)

server-run:
	PYTHONPATH=. uvicorn server.main:app --host 0.0.0.0 --port 8000

migrate:
	PYTHONPATH=. alembic -c server/alembic.ini upgrade head

test: $(AGENT_TEST_BINS)
	PYTHONPATH=. pytest server/tests

agent-tests: $(AGENT_TEST_BINS)

agent/tests/%.exe: agent/tests/%.cpp $(AGENT_SRC)
	$(CXX) $(CXXFLAGS) -DDLP_ENABLE_TESTS $^ -o $@ $(LDFLAGS)

docker-build:
	docker build -f server/Dockerfile -t dlp-server .
	docker build -f dashboard/Dockerfile -t dlp-dashboard .

release:
	@echo "Tag and publish release artifacts via CI."

clean:
	rm -f dlp_agent.exe agent/src/*.o agent/tests/*.exe
