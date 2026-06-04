# asio-ice + werift-webrtc DataChannel Demo

Demonstrates WebRTC DataChannel connectivity between **asio-ice** (C++23) and
[werift-webrtc](https://github.com/shiguredo/werift-webrtc) (TypeScript).

## Architecture

```
┌───────────────────────┐     WebSocket      ┌──────────────────────────┐
│   asio-ice (C++)      │◄══════════════════►│   werift-webrtc (TS)      │
│  ICE agent            │  SDP offer/answer   │  RTCPeerConnection        │
│  DTLS transport        │◄══════ ICE ═══════►│  ICE transport            │
│  SCTP transport        │◄═════ DTLS ═══════►│  DTLS transport           │
│  DataChannelManager    │◄═════ SCTP ═══════►│  SCTP transport           │
│                       │◄══ DCEP (pingpong)═►│  DataChannel              │
└───────────────────────┘                     └──────────────────────────┘
```

### C++ Transport Stack

```
  data_channel_manager<DgramT>   ← DCEP + DataChannel
            │
  sctp::transport<DgramT>        ← SCTP association
            │
  datagram_transport<DtlsT>      ← DTLS encryption
            │
  agent::ice_transport_type      ← ICE nominated pair
            │
  asioice::agent                 ← ICE connectivity
```

## Build

Requires SCTP-over-DTLS enabled in cmake:
```bash
cd clang-build
cmake .. -DASIOICE_ENABLE_SCTP_OVER_DTLS=ON ...
make werift_example -j$(nproc)
```

Target: `werift_example`

## Usage

```bash
# Terminal 1 — C++ signaling server:
cd clang-build
./example/werift/werift_example

# Terminal 2 — TypeScript werift peer:
cd example/werift
npm install
npm start

# Or with a custom server URL:
npx tsx werift_peer.ts ws://host:8082/ws
```

## Files

| File | Description |
|------|-------------|
| `main.cpp` | C++ ICE/DTLS/SCTP agent + WebSocket signaling server |
| `CMakeLists.txt` | CMake build for the C++ side |
| `werift_peer.ts` | TypeScript werift-webrtc peer |
| `package.json` | npm dependencies (werift, ws, tsx) |
| `tsconfig.json` | TypeScript compiler configuration |

## Notes

- Requires `-DASIOICE_ENABLE_SCTP_OVER_DTLS=ON` in cmake (needs OpenSSL 3.0+ + dcsctp submodule)
- TypeScript peer requires Node.js 18+ with `npm install` for `werift`, `ws`, and `tsx`
