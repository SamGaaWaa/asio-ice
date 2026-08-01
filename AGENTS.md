# Agent Guidelines for asio-ice

asio-ice is an ICE (RFC 8445) implementation in C++23. Async model: P2300 senders/receivers via [stdexec](https://github.com/NVIDIA/stdexec); I/O via Boost.Asio (or standalone Asio); DTLS/SCTP via OpenSSL. Interop-tested against aiortc (Python), pion/webrtc (Go), werift-webrtc (TypeScript), and browser WebRTC.

## Build

**Prerequisites**: CMake 3.22+, Boost 1.89+ (CMake does `find_package(Boost 1.89 CONFIG REQUIRED)`), Clang 20+ (preferred) or GCC 13+, stdexec include tree, OpenSSL 3.0+ (only for DTLS/SCTP).

**Use Clang, not GCC.** The project is developed and tested with Clang; GCC 13 may hit template/coroutine issues with current stdexec.

Build scripts hardcode personal paths (`Boost_DIR`, `STDEXEC_DIR`, `OPENSSL_ROOT_DIR`) — edit them per machine:

```bash
./debug-build.sh        # Clang debug + ASan → clang-build/
./release-build.sh      # Clang -O3 → clang-build/
./gcc-debug-build.sh    # GCC → gcc-build/
./gcc-release-build.sh
```

Manual CMake:

```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug \
         -DASIOICE_ENABLE_SCTP_OVER_DTLS=ON \
         -DBoost_DIR=<path>/lib/cmake/Boost-1.89.0 \
         -DSTDEXEC_DIR=<path>/stdexec/include
make -j$(nproc)
```

### CMake options

| Option | Default | Notes |
|--------|---------|-------|
| `ASIOICE_USE_CPPMDNS` | ON | mDNS candidates (cppmdns subproject) |
| `ASIOICE_USE_OPENSSL` | OFF | auto-enabled by DTLS/SCTP |
| `ASIOICE_ENABLE_DTLS` | OFF | DTLS transport |
| `ASIOICE_ENABLE_SCTP_OVER_DTLS` | OFF | SCTP data channels + examples |
| `ASIOICE_TEST` | ON | build test executables |
| `ASIOICE_EXAMPLE` | ON | build examples |
| `ENABLE_IO_URING` | OFF | io_uring (Linux + liburing only) |

`ASIOICE_USE_BOOST_ASIO` is hardcoded `ON` via `set()` (not an `option()`), so the standalone-Asio branch is not currently reachable via `-D`.

### Build targets

- `asioice` — static library
- Tests: `stun_test`, `stun_client_test`, `candidate_test`, `hash_test`, `turn_client_test`, `async_queue_test`, `io_buffer_test`, `boost_fiber_test`, `on_scope_empty_test` (plus `dtls_test`, `ice_test`, `sctp_test` when DTLS/SCTP enabled)
- Examples: `simple_example`, `ffmpeg_example`, `aiortc_example`, `browser_example`, `chat_example`, `pion_example`, `werift_example`

Single target: `make browser_example -j$(nproc)`

## Test

Tests are standalone executables (no framework); failures throw `std::runtime_error`.

```bash
cd clang-build
./hash_test                          # run one
for t in *_test; do ./"$t"; done    # run all
```

`stun_client_test` and `turn_client_test` require network access (real STUN/TURN servers; TURN config in `turnserver.conf`). The rest (`ice_test`, `sctp_test`) are local in-process.

## Architecture

- Public API is `asioice::agent` (type-erased; `include/asioice/agent.hpp`). `basic_agent<Socket>` is the templated core shown in the README; most examples use `agent`.
- Transport stack layers via concepts: `ice_transport` → `ssl::dtls_transport` → `sctp::transport` → `data_channel_manager`. Async ops return stdexec senders or `asioice::task<>` coroutines.
- `include/asioice.hpp` is the umbrella header (`agent.hpp`, `basic_agent.hpp`, `asio2exec.hpp`, `async_queue.hpp`).
- Logging goes through `samlog` (subdirectory `samlog/`; `#include "samlog.hpp"`). Recent change replaced iostream logging.

## Gotchas

- **`config.hpp` is generated**: `include/asioice/config.hpp` is produced from `config.hpp.in` via `configure_file()` and is gitignored. Edit the `.in`, re-run cmake.
- **asio2exec bridge**: `include/asioice/detail/asio2exec.hpp` bridges Asio executors ↔ stdexec receivers; reads `ASIOICE_USE_BOOST_ASIO` from the generated `config.hpp`.
- **Boost linkage**: `Boost_USE_STATIC_LIBS ON`, links `Boost::boost` (not individual components).
- **dcsctp submodule**: `exsctp/dcsctp` is a git submodule, built only with SCTP. Default `sctp_options` sets `zero_checksum_alternate_error_detection_method = LowerLayerDtls()` (experimental) — use `None()` if the peer doesn't support it; set `disable_checksum_verification = true` when interoping with peers using a different CRC32c byte order (e.g., usrsctp).
- **Third-party JSON**: `third_party/json.hpp` (nlohmann) is available as `#include "json.hpp"` (no path prefix; private include).
- **Formatting**: `.clang-format` enforces 80-col, 4-space, `SortIncludes: Never` (include order is intentional — never auto-sort).
- **`agent::sendto()`** sends raw UDP on the nominated pair with NO STUN header. The peer demuxes by first byte: STUN `0x00/0x01`, DTLS `20`–`63`, SRTP `0x80` (everything else → application). Requires a nominated pair (`co_await ag.connect()` first) or it errors.
- **boost::process** (ffmpeg example): constructor launches the process; `.running()`/`.terminate()`/`.wait()` manage it; an `std::error_code` out-param on the constructor catches launch failures without throwing.

## Usage quick reference

```cpp
using IceT  = agent::ice_transport_type;
using DtlsT = ssl::dtls_transport<IceT>;
using SctpT = sctp::transport<DtlsT>;
using DcMgr = data_channel_manager<SctpT>;      // in asioice namespace

auto ice  = ag.create_ice_transport(1);
auto dtls = std::make_shared<DtlsT>(ice, std::move(cert));
auto sctp = std::make_shared<SctpT>(dtls);
sctp->start();
co_await sctp->accept();

DcMgr dc_mgr(sctp, /*is_client=*/true);
dc_mgr.on_remote_channel([](std::shared_ptr<data_channel> ch) {
    auto msg = co_await ch->read();  // std::optional<data_channel_message>; nullopt = closed
    co_await ch->send_text("reply");
});
auto ch = dc_mgr.create_data_channel("label");
```

- `data_channel_options`: `ordered`, `max_packet_life_time`, `max_retransmits`, `protocol`, `negotiated`, `stream_id`.
- mDNS: `agent_config{ .enable_mdns = true, .mdns_publish_timeout, .mdns_resolve_timeout }` — host `.local` candidates become mDNS hostnames; the agent lazily creates `default_mdns_interface()` (cppmdns). Guarded by `ASIOICE_USE_CPPMDNS`.
- State: `ag.state()` → INIT→GATHERING→CONNECTING→CONNECTED→CLOSED; `co_await ag.on_state_change()` / `on_closed()` / `on_connected_or_closed()`.
- Raw send after connect: `co_await ag.sendto(net::buffer("hello"), /*component=*/1);`

## Examples

All follow: gather candidates → SDP → ICE connect → (DTLS + media/DataChannel).

| Example | Signaling | Remote peer | DTLS role (C++) | Requires |
|---------|-----------|-------------|-----------------|----------|
| simple | in-process | in-process agent | N/A | core only |
| ffmpeg | WebSocket 8080 | Python aiortc | client | DTLS only |
| aiortc | WebSocket 8080 | Python aiortc | client | SCTP+DTLS |
| browser | WebSocket 8083 | Chrome/Firefox JS | client | SCTP+DTLS |
| pion | WebSocket 8081 | Go pion/webrtc | client | SCTP+DTLS |
| werift | WebSocket 8082 | TypeScript werift | client | SCTP+DTLS |
| chat | copy-paste SDP | another instance | offer=client, answer=server | SCTP+DTLS |

- `simple`: `./simple_example [seconds]` — loopback, no SDP/DTLS/SCTP; quick ICE-core iteration.
- `ffmpeg`: `./ffmpeg_example` + `python aiortc_receiver.py` (needs ffmpeg with libx264). Demonstrates DTLS-SRTP key export: after handshake `dtls->export_srtp_key_material()` returns `std::optional<srtp_key_material>` (`client_write_key/salt`, `server_write_key/salt`, `srtp_protection_profile`). C++ is DTLS client, so ffmpeg (the sender) uses `client_write_*`.
- `chat`: SDP copy-pasted between two terminals as single-line escaped strings; `a=setup:active` (offer/client) vs `a=setup:passive` (answer/server). Async stdin uses `net::posix::stream_descriptor` + `async_read_some` with manual line buffering — NOT `std::thread` (causes ASan stack-use-after-return).
- `browser`: open `http://localhost:8083`; JS waits for `iceGatheringState === 'complete'`, sends full SDP with `a=setup:actpass`; C++ answer replies `a=setup:active`; set `enable_mdns = true` for `.local` candidates.
