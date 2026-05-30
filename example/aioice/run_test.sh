#!/bin/bash
# asio-ice + aioice compatibility test
# Runs signaling server, Python aioice peer, and C++ asio-ice peer.
# Both peers send a message every 1 second for 30 seconds.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$SCRIPT_DIR/../../clang-build}"
SERVER_PORT="${SERVER_PORT:-18080}"
BOOST_LIB="/home/sam/opensource/boost_install/lib"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    kill $SRV_PID 2>/dev/null
    wait $SRV_PID 2>/dev/null
    exit ${1:-0}
}
trap 'cleanup 1' INT TERM

# Kill any leftover processes on the port
fuser -k ${SERVER_PORT}/tcp 2>/dev/null || true
sleep 1

echo -e "${GREEN}=== Starting signaling server on port ${SERVER_PORT} ===${NC}"
python3 "$SCRIPT_DIR/server.py" "$SERVER_PORT" &
SRV_PID=$!
sleep 2

echo -e "${GREEN}=== Starting Python aioice peer ===${NC}"
export PYTHONUNBUFFERED=1
timeout 60 python3 -u "$SCRIPT_DIR/aioice_main.py" > /tmp/aioice_test_py.log 2>&1 &
PY_PID=$!
sleep 3

echo -e "${GREEN}=== Starting C++ asio-ice peer ===${NC}"
export LD_LIBRARY_PATH="$BOOST_LIB:$LD_LIBRARY_PATH"
CPP_BIN="$BUILD_DIR/example/aioice/aioice_example"
if [ ! -x "$CPP_BIN" ]; then
    echo -e "${RED}Binary not found: $CPP_BIN${NC}"
    echo "Build with: add_subdirectory(example/aioice) to root CMakeLists.txt"
    cleanup 1
fi
timeout 60 "$CPP_BIN" --port "$SERVER_PORT" > /tmp/aioice_test_cpp.log 2>&1 &
CPP_PID=$!

echo ""
echo -e "${YELLOW}Waiting for peers (up to 60s)...${NC}"
PY_EXIT=0
CPP_EXIT=0
wait $PY_PID 2>/dev/null || PY_EXIT=$?
wait $CPP_PID 2>/dev/null || CPP_EXIT=$?

echo ""
echo -e "${GREEN}=== Python aioice output ===${NC}"
cat /tmp/aioice_test_py.log
PY_CONNECTED=$(grep -c "ICE connected" /tmp/aioice_test_py.log 2>/dev/null || true)
PY_SENT_COUNT=$(grep -c "Send error" /tmp/aioice_test_py.log 2>/dev/null || true)

echo ""
echo -e "${GREEN}=== C++ asio-ice output ===${NC}"
cat /tmp/aioice_test_cpp.log
CPP_CONNECTED=$(grep -c "ICE connected" /tmp/aioice_test_cpp.log 2>/dev/null || true)
CPP_RECV_COUNT=$(grep -cE "^\[[0-9]+\] " /tmp/aioice_test_cpp.log 2>/dev/null || true)
CPP_SENT_COUNT=$(grep -c "^Sent:" /tmp/aioice_test_cpp.log 2>/dev/null || true)

echo ""
echo -e "${YELLOW}=== Summary ===${NC}"
echo "Python connected=$PY_CONNECTED errors=$PY_SENT_COUNT exit=$PY_EXIT"
echo "C++    connected=$CPP_CONNECTED sent=$CPP_SENT_COUNT recv=$CPP_RECV_COUNT exit=$CPP_EXIT"

if [ "$PY_CONNECTED" -gt 0 ] && [ "$CPP_CONNECTED" -gt 0 ]; then
    echo -e "${GREEN}PASS: Both peers connected${NC}"
else
    echo -e "${RED}FAIL: ICE did not connect${NC}"
    cleanup 1
fi

cleanup 0
