CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -DUNICODE -D_UNICODE -Wall -I./agent/src
LDFLAGS ?= -lcurl -lsqlite3 -lole32 -loleaut32 -lwbemuuid -lbcrypt -lfltlib

PYTHON ?= python3
PIP ?= pip
SOURCE_DATE_EPOCH ?= 1700000000
export SOURCE_DATE_EPOCH

AGENT_SRC = $(shell find agent/src -name '*.cpp')
AGENT_TEST_SRC = $(shell find agent/tests -name '*.cpp')
AGENT_TEST_BINS = $(AGENT_TEST_SRC:.cpp=.exe)

ifeq ($(OS),Windows_NT)
BUILD_AGENT := 1
else
BUILD_AGENT := 0
endif

.PHONY: agent-build server-run migrate test agent-tests docker-build release clean deps lockfile

agent-build:
ifeq ($(BUILD_AGENT),1)
	$(CXX) $(CXXFLAGS) $(AGENT_SRC) -o dlp_agent.exe $(LDFLAGS)
else
	@echo "agent-build skipped: Windows toolchain/headers required"
endif

server-run:
	PYTHONPATH=. uvicorn server.main:app --host 0.0.0.0 --port 8000

migrate:
	PYTHONPATH=. alembic -c server/alembic.ini upgrade head

deps:
	$(PIP) install -r server/requirements.txt

lockfile:
	$(PYTHON) -m pip freeze | LC_ALL=C sort > server/requirements.lock

test:
	PYTHONPATH=. pytest server/tests
ifeq ($(BUILD_AGENT),1)
	$(MAKE) agent-tests
else
	@echo "agent-tests skipped: Windows toolchain/headers required"
endif

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
