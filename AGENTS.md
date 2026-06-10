# Agent Guidelines for asio-ice

## Project Overview

asio-ice is an ICE (RFC 8445) implementation in C++23. It uses [stdexec](https://github.com/NVIDIA/stdexec) sender/receiver (P2300) for structured concurrency, Boost.Asio (or standalone Asio) for async I/O, and OpenSSL for DTLS. Verified interop with aiortc (Python), pion/webrtc (Go), werift-webrtc (TypeScript), and browser WebRTC (Chrome/Firefox).

## Why asio-ice

- **P2300 senders/receivers** — the only ICE library using the C++ async model being standardized. Every async operation returns a sender; compose with `exec::when_any`, `exec::repeat_until`, `exec::finally`, `exec::async_scope`.
- **C++23 coroutines** — `co_await` an ICE connect, a DTLS handshake, or an SCTP message. No callback hell.
- **Type-safe transport layering** via C++20 concepts — the compiler checks that you stack `ice_transport → dtls_transport → sctp::transport → data_channel_manager` correctly.
- **Full RFC 8445 compliance** — trickle ICE, role negotiation, aggressive nomination, mDNS, DTLS-SRTP keying.
- **4 verified interop targets** — Python, Go, TypeScript, and browser. Not just "should work" — tested.
- **Boost.Asio or standalone Asio** — your choice.

## Build Commands

**Prerequisites**: CMake 3.22+, Boost 1.89+ (`json`, `context`), Clang 20+ / GCC 13+, stdexec include tree. OpenSSL 3.0+ for DTLS/SCTP.

**IMPORTANT**: Build scripts hardcode personal paths. Edit `Boost_DIR`, `STDEXEC_DIR`, and `OPENSSL_ROOT_DIR` per machine before running.

```bash
./debug-build.sh            # Clang debug + ASan → clang-build/
./release-build.sh          # Clang -O3 → clang-build/
./gcc-debug-build.sh        # GCC debug + ASan → gcc-build/
./gcc-release-build.sh      # GCC -O3 → gcc-build/
```

### Manual CMake
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug \
         -DASIOICE_USE_BOOST_ASIO=ON \
         -DASIOICE_ENABLE_SCTP_OVER_DTLS=ON \
         -DBoost_DIR=<path>/lib/cmake/Boost-1.89.0 \
         -DSTDEXEC_DIR=<path>/stdexec/include
make -j$(nproc)
```

### Key CMake options
| Option | Default | Description |
|--------|---------|-------------|
| `ASIOICE_USE_BOOST_ASIO` | `ON` | Boost.Asio; `OFF` for standalone Asio |
| `ASIOICE_USE_CPPMDNS` | `ON` | mDNS candidates (via cppmdns subproject) |
| `ASIOICE_ENABLE_DTLS` | `OFF` | DTLS transport |
| `ASIOICE_ENABLE_SCTP_OVER_DTLS` | `OFF` | SCTP data channels + examples |

### Build targets
- `asioice` — static library
- Tests: `stun_test`, `candidate_test`, `hash_test`, `turn_client_test`, etc.
- SCTP+DTLS: `ice_test`, `sctp_test`
- Examples: `simple_example`, `aiortc_example`, `browser_example`, `chat_example`, `pion_example`, `werift_example`

To build a single target: `make browser_example -j$(nproc)`

## Test Commands

Tests are standalone executables (no framework). Failures throw `std::runtime_error`.

```bash
cd clang-build
./hash_test              # run one
for t in *_test; do ./"$t"; done   # run all
```

## Usage

### Typed transport stack

```cpp
using IceT  = agent::ice_transport_type;
using DtlsT = ssl::dtls_transport<IceT>;
using SctpT = sctp::transport<DtlsT>;
using DcMgr = data_channel_manager<SctpT>;

auto ice = ag.create_ice_transport(1);
auto dtls = std::make_shared<DtlsT>(ice, std::move(cert));
// ... ICE connect, DTLS handshake ...
auto sctp = std::make_shared<SctpT>(dtls);
sctp->start();
bool ok = co_await sctp->accept();

DcMgr dc_mgr(sctp, /*is_client=*/true);
dc_mgr.on_remote_channel([](auto ch) { /* ... */ });
dc_mgr.start();
```

### DataChannel API (RFC 8832 / DCEP)

```cpp
// Remote channel callback
dc_mgr.on_remote_channel([](std::shared_ptr<data_channel> ch) {
    // ch->read() returns sender producing
    // std::optional<data_channel_message>
    // nullopt = channel closed
    auto msg = co_await ch->read();  // data_channel_message{data, binary}
    co_await ch->send_text("reply"); // convenience
    co_await ch->send(buf, true);    // binary send
});

// Create a local channel
auto ch = dc_mgr.create_data_channel("mylabel");
ch->send_text("hello");
```

- `data_channel_options`: `ordered`, `max_packet_life_time`, `max_retransmits`, `protocol`, `negotiated`, `stream_id`
- `data_channel::label()`, `protocol()`, `ordered()`, `stream_id()`, `state()`

### mDNS candidates (browser interop)

```cpp
agent_config cfg = {
    .enable_mdns = true,
    // .mdns = my_custom_mdns_interface  // null = auto-create default
    .mdns_publish_timeout = 3000ms,
    .mdns_resolve_timeout  = 3000ms,
};
```

When `enable_mdns = true`, host candidates with `.local` addresses are replaced with mDNS hostnames. The agent lazily creates a `default_mdns_interface()` (backed by cppmdns) if no custom interface is supplied.

Guarded by `ASIOICE_USE_CPPMDNS` (CMake option). `#include "asioice/mdns_interface.hpp"` for the abstract interface.

### Agent state tracking

```cpp
agent ag(ctx, cfg);
ag.state();                  // INIT → GATHERING → CONNECTING → CONNECTED → CLOSED
co_await ag.on_state_change();       // completes on any state transition
co_await ag.on_closed();             // completes when CLOSED
co_await ag.on_connected_or_closed(); // completes on CONNECTED or CLOSED
```

### Sending raw data after ICE connects

```cpp
co_await ag.sendto(net::buffer("hello"), /*component=*/1);
```

## Project-Specific Gotchas

### asio2exec bridge

`include/asioice/detail/asio2exec.hpp` bridges Asio executors to stdexec receivers. It reads `ASIOICE_USE_BOOST_ASIO` from the generated `config.hpp` — no manual `#define` needed. The umbrella header `asioice.hpp` includes it automatically.

### config.hpp is generated — do not edit directly

`include/asioice/config.hpp` is generated from `config.hpp.in` via `configure_file()`. Edit `config.hpp.in` and re-run cmake.

### Boost linkage

CMake sets `Boost_USE_STATIC_LIBS ON` and links `Boost::boost` (not individual components).

### dcsctp submodule

`exsctp/dcsctp` is a git submodule, built only with `ASIOICE_ENABLE_SCTP_OVER_DTLS=ON`.
- Default `sctp_options` sets `zero_checksum_alternate_error_detection_method = LowerLayerDtls()` — an experimental parameter. Set to `None()` if peer doesn't support it.
- `disable_checksum_verification = true` when interoping with peers using different CRC32c byte order (e.g., usrsctp).

### Third-party JSON

`third_party/json.hpp` (nlohmann) is available as `#include "json.hpp"` without path prefix (private include for asioice targets).

### Formatting

`.clang-format` enforces 80-col limit, 4-space indent. `SortIncludes: Never` — include order is intentional, never auto-sort.

```bash
find src include -name "*.cpp" -o -name "*.hpp" -o -name "*.ipp" | xargs clang-format -i
```

## Examples

All six examples follow a common pattern: gather candidates, build SDP, ICE connect, (DTLS + SCTP, DataChannel).

| Example  | Signaling | Remote Peer | DTLS Role (C++) | Requirements |
|----------|-----------|-------------|-----------------|-------------|
| simple   | in-process | another in-process agent | N/A (no DTLS) | core only |
| aiortc   | WebSocket (8080) | Python aiortc | client | SCTP+DTLS |
| browser  | WebSocket (8083) | Chrome/Firefox JS | client | SCTP+DTLS |
| pion     | WebSocket (8081) | Go pion/webrtc | client | SCTP+DTLS |
| werift   | WebSocket (8082) | TypeScript werift | client | SCTP+DTLS |
| chat     | stdin/stdout (copy-paste SDP) | another chat instance | offer=client, answer=server | SCTP+DTLS |

### Simple example (`example/simple/`)

A self-contained ICE connectivity test between two in-process agents with ping-pong. No external peer, DTLS, or SCTP required — only the core asioice library. Always built when `ASIOICE_EXAMPLE=ON`.

```bash
./simple_example [seconds]
```
Uses `use_loopback = true`, exchanges candidates directly via code (no SDP), sends one-byte STUN-demux header (`\4`). Good for quick iteration and benchmarking the ICE core.

### WebSocket signaling pattern (aiortc/browser/pion/werift)

Remote peer creates `RTCPeerConnection` + DataChannel "pingpong", generates SDP offer with inline candidates, sends via WebSocket. C++ side parses offer, creates transport stack, sends SDP answer with `a=setup:active` (C++ is DTLS client). Then SCTP accept, DataChannel ping-pong.

### Copy-paste chat (`example/chat/`)

No server dependency — SDP is copy-pasted between two terminal instances. Run two instances side by side:

```bash
./chat_example
```

1. First instance picks `offer`, enters username (or press Enter for random), gathers candidates, prints local SDP as a **single-line escaped string** (easy triple-click copy)
2. User pastes that SDP into the second instance (which picks `answer` and enters its own username)
3. Second instance gathers candidates, prints its local SDP as single-line
4. User pastes the answer SDP back into the first instance
5. ICE connects → DTLS handshake → SCTP → DataChannel → interactive chat with colored messages (green=self, white=peer)

Key differences from the WebSocket examples:
- Uses `agent::local_candidates()` after `gather_candidates()` to build inline SDP (not the `on_local_candidates()` callback)
- Offer side is DTLS client (`a=setup:active`), answer side is DTLS server (`a=setup:passive`)
- SDP printed as single-line with `\r\n` escape sequences via `enc()`/`dec()` helpers
- Supports both multi-line (legacy) and single-line SDP paste input
- Custom `a=username:<name>` SDP field for display names
- ANSI color codes: green for self (`\033[32m`), white for remote (`\033[37m`)
- Asynchronous stdin via `net::posix::stream_descriptor` + `async_read_some` with manual line buffering — **NOT** `shared_promise` + `std::thread` (causes ASan stack-use-after-return)
- Username prompt: enter a name or press Enter for a random one (e.g., `light_bear32`)

### Browser example specifics

- Open `http://localhost:8083` in Chrome/Firefox
- C++ server serves the HTML page on HTTP GET; WebSocket upgrade at `/ws`
- Browser SDP uses `a=setup:actpass` — C++ answer must reply `a=setup:active`
- Browsers do trickle ICE by default; the JS code waits for `iceGatheringState === 'complete'` then sends the full SDP
- Set `enable_mdns = true` for `.local` mDNS candidates from the browser
