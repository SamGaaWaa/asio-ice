# asio-ice + pion/webrtc DataChannel Demo

This example demonstrates interoperability between asio-ice (C++) and
[pion/webrtc](https://github.com/pion/webrtc) (Go) by establishing a
WebRTC DataChannel and exchanging a ping-pong message.

## Status

| Layer | Status |
|-------|--------|
| ICE connectivity | Working |
| DTLS handshake | Working |
| SCTP association | Working |

> **Python peer note**: The `pion_peer.py` uses Python aiortc (usrsctp) as an alternative test peer when Go is unavailable.

## Architecture

```
┌───────────────────────┐     WebSocket      ┌───────────────────────┐
│   asio-ice (C++)      │◄══════════════════►│   pion/webrtc (Go)    │
│                       │  SDP offer/answer   │                       │
│  ICE agent            │                     │  PeerConnection       │
│  DTLS transport        │◄══════ ICE ═══════►│  ICE transport         │
│  SCTP transport        │◄═════ DTLS ═══════►│  DTLS transport        │
│  DataChannelManager    │◄═════ SCTP ═══════►│  SCTP transport        │
│                       │◄══ DCEP (pingpong)═►│  DataChannel           │
└───────────────────────┘                     └───────────────────────┘
```

The C++ side runs a WebSocket signaling server on port 8081.
The Go peer connects, sends an SDP offer, receives the SDP answer,
and after ICE/DTLS/SCTP handshake, exchanges ping-pong over a DataChannel.

## Prerequisites

**C++ side:**
- Boost 1.89+, stdexec, OpenSSL 3.0+, Clang 20+ or GCC 13+
- Build with `-DASIOICE_ENABLE_SCTP_OVER_DTLS=ON`

**Go side:**
- Go 1.22+
- Run `cd gopeer && go mod tidy` to download dependencies

## Building

```bash
# Build the C++ server (from repo root, after cmake configure)
cd clang-build && make pion_example -j$(nproc)

# Download Go dependencies
cd example/pion/gopeer && go mod tidy
```

## Running

**Terminal 1 — C++ signaling server:**
```bash
./clang-build/example/pion/pion_example
# Server on ws://localhost:8081/ws
```

**Terminal 2 — Go peer:**
```bash
cd example/pion/gopeer && go run .
```

**Terminal 2 (alternative) — Python peer:**
```bash
python3 example/pion/pion_peer.py
```

Expected C++ output:
```
Server on ws://localhost:8081/ws
WS connected
DTLS fp: XX:XX:...
Offer: ufrag=... fp=... cands=...
Sent answer, connecting
ICE connected!
DTLS handshake (client)...
DTLS OK, fp: ...
SCTP accept...
```

## Files

| File | Description |
|------|-------------|
| `main.cpp` | C++ ICE/DTLS/SCTP agent + WebSocket signaling server |
| `pion_peer.py` | Python aiortc peer (alternative to Go) |
| `CMakeLists.txt` | CMake build for the C++ side |
| `gopeer/main.go` | Go pion/webrtc peer |
| `gopeer/go.mod` | Go module dependencies |
| `gopeer/go.sum` | Go dependency checksums |
