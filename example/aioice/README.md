# aioice Compatibility Demo

Demonstrates ICE (RFC 8445) interoperability between **asio-ice** (C++23) and
**Python aioice** through a WebSocket signaling relay.

## Architecture

```
  Python aioice ──┐                  ┌── C++ asio-ice
                   │   JSON (SDP)     │
                   ├─── ws://relay ───┤
                   │   (port 18080)   │
                   │                  │
                   └─── P2P data ─────┘
                        (ICE transport)
```

## Prerequisites

### Python
```bash
pip install aioice 'websockets<14'
```

### C++
Build asio-ice first (see root `README.md`), then add this example to the
root `CMakeLists.txt` by appending:

```cmake
add_subdirectory(example/aioice)
```

Rebuild. The target `aioice_example` will be available in the build directory.

## Usage

Run in three terminals:

### Terminal 1: Signaling server
```bash
cd example/aioice
python3 server.py             # starts on ws://0.0.0.0:18080
```

### Terminal 2: Python peer (connects first, gets offerer role)
```bash
cd example/aioice
python3 aioice_main.py
```

### Terminal 3: C++ peer (connects second, gets answerer role)
```bash
cd clang-build
./example/aioice/aioice_example
```

## Options (C++ peer)

| Option | Default | Description |
|--------|---------|-------------|
| `--server` | `localhost` | Signaling server address |
| `--port` | `18080` | Signaling server port |
| `--room` | `default` | Room name shared by both peers |

## Protocol

Peers exchange SDP offers/answers as JSON over WebSocket:

```json
{"type": "role", "role": "offerer"}
{"type": "sdp", "sdp": "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n..."}
```

SDP contains `a=ice-ufrag:`, `a=ice-pwd:`, and `a=candidate:` lines.

The signaling server buffers messages when only one peer is connected and
replays them when the second peer joins, avoiding race conditions.
