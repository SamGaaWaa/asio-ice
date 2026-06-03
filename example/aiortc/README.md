# aiortc DataChannel Ping-Pong Demo

Demonstrates WebRTC DataChannel connectivity between **asio-ice** (C++23) and **Python aiortc** using ICE + DTLS + SCTP.

## Architecture

```
  Python aiortc ──┐                  ┌── C++ asio-ice
   (RTCPeerConn)  │  JSON (SDP +     │  (agent + dtls + sctp)
                  │  trickle ICE)    │
                  ├─── ws://relay ───┤
                  │   (port 8080)    │
                  │                  │
                  └─── SCTP over DTLS over ICE ┘
                            │
                  DataChannel "pingpong"
                       ┌── ping ──►
                       ◄── pong ──┘
```

### C++ Transport Stack

```
  data_channel_manager<DtlsTransport>   ← DCEP + DataChannel (async_read pull-mode)
            │
  sctp::transport<DtlsTransport>        ← SCTP association
            │
  ssl::dtls_transport<IceTransport>     ← DTLS encryption
            │
  agent::ice_transport_type             ← ICE nominated pair
            │
  asioice::agent                        ← ICE connectivity
```

Each data_channel uses a bounded async queue (256 messages) with backpressure: if the
application doesn't read fast enough, the SCTP read loop blocks, applying flow control
all the way to the peer.

## Build

Requires SCTP-over-DTLS enabled in cmake:

```bash
# cmake -DASIOICE_ENABLE_SCTP_OVER_DTLS=ON ...
cd clang-build
cmake .. -DASIOICE_ENABLE_SCTP_OVER_DTLS=ON ...
make aiortc_example
```

Target: `aiortc_example`

## Usage

```bash
cd clang-build
./example/aiortc/aiortc_example

# In another terminal:
cd example/aiortc
python3 aiortc_main.py
```

The C++ server listens on port 8080, serves WebSocket at `/ws`.

Python peer connects, creates `RTCPeerConnection` with a DataChannel named "pingpong", exchanges SDP offer/answer + trickle ICE candidates, establishes DTLS + SCTP, then runs a ping-pong test.

Expected output:
```
[Python] Created data channel: pingpong
[Python] DataChannel 'pingpong' OPEN!
[Python] Sent: ping
[C++]    Remote DataChannel: pingpong (stream 1)
[C++]    Recv on 'pingpong': ping
[C++]    Sent pong
[Python] Received on 'pingpong': pong
[Python] Ping-pong SUCCESS!
```

## Files

| File | Description |
|------|-------------|
| `main.cpp` | HTTP/WS server + ICE + DTLS + SCTP + DataChannel |
| `aiortc_main.py` | Python aiortc peer with DataChannel ping-pong |
| `CMakeLists.txt` | Build config (requires SCTP enabled) |

## Notes

- Requires `-DASIOICE_ENABLE_SCTP_OVER_DTLS=ON` in cmake (needs OpenSSL 3.0+ + dcsctp submodule)
- Python: `pip install aiortc aioice websockets`
- The DataChannel implementation is in `include/asioice/data_channel.hpp`
