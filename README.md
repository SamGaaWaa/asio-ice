# asio-ice

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**asio-ice** is a C++23 implementation of **Interactive Connectivity Establishment (ICE)** following RFC 8445 (ICE version 2). It uses Boost.Asio (or standalone Asio) for asynchronous networking, OpenSSL for cryptographic operations, [stdexec](https://github.com/NVIDIA/stdexec) for structured concurrency via senders/receivers, and modern C++ coroutines for clean, composable async code.

The library provides a full-featured ICE agent that can gather candidates (host, server-reflexive, relayed), perform connectivity checks, nominate candidate pairs, and establish peer-to-peer connections over UDP, with optional DTLS security, SCTP-over-DTLS data channels, and TURN relay support.

## Features

- **RFC 8445 compliant** -- ICE version 2 with trickle ICE, role negotiation, tie-breaker resolution, and connectivity checks.
- **Modern C++23** -- coroutines (`co_await`/`co_return`), concepts, `std::variant`, `std::optional`, `std::string_view`.
- **Senders/receivers (P2300)** -- all async operations return `stdexec::sender` types, enabling structured concurrency with `exec::async_scope`, `exec::when_any`, `exec::repeat_until`, and `exec::finally`.
- **Asio-based I/O** -- works with both **Boost.Asio** (>=1.89) and **standalone Asio**; all I/O is asynchronous and non-blocking via an `asio2exec` sender/receiver bridge.
- **Pluggable transport** -- type-erased `any_transport` with built-in UDP socket transport, TURN client, DTLS transport (OpenSSL), and experimental SCTP-over-DTLS.
- **Full candidate support** -- host, server-reflexive (STUN), peer-reflexive, and relayed (TURN) candidates; IPv4/IPv6 dual-stack.
- **STUN/TURN** -- complete STUN message encoding/decoding (HMAC-SHA-256 integrity), TURN client with allocation, permissions, channels, nonce cookies, and long-term credential mechanism.
- **Security** -- DTLS-SRTP key material export for encrypted media; STUN message integrity with HMAC-SHA-256; self-signed certificate generation.
- **Configurable** -- fine-tune behavior through `agent_config` (STUN/TURN servers, component count, transport policy, timeouts, keepalive interval).
- **Cross-platform** -- builds on Linux, macOS, and Windows (MSVC, Clang-CL, GCC, MinGW).

## Dependencies

- **Compiler** with C++23 support (Clang 20+, GCC 13+, MSVC 19.34+)
- **CMake** 3.22+
- **Boost** 1.89+ (components: `json`, `context`)
- **stdexec** -- [NVIDIA/stdexec](https://github.com/NVIDIA/stdexec) sender/receiver library
- **OpenSSL** 3.0+ (optional, for DTLS)
- **liburing** (optional, for io_uring on Linux)

## Building

### Quick Start

The build scripts require that you set `Boost_DIR` and `STDEXEC_DIR` to point to your local Boost CMake config and stdexec `include/` directory. Edit the paths at the top of each script before running.

```bash
./debug-build.sh        # Clang debug build with address sanitizer
./release-build.sh      # Clang release build (-O3)
./gcc-debug-build.sh    # GCC debug build
./gcc-release-build.sh  # GCC release build
```

The scripts create `clang-build/` or `gcc-build/` directories containing the static library `libasioice.a` and test executables.

### Manual CMake Build

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug \
         -DASIOICE_USE_BOOST_ASIO=ON \
         -DBoost_DIR=<path_to_boost_cmake_config> \
         -DSTDEXEC_DIR=<path_to_stdexec>/include \
         -DOPENSSL_ROOT_DIR=<openssl_prefix>
make -j$(nproc)
```

**Configuration options:**

| Option | Default | Description |
|--------|---------|-------------|
| `ASIOICE_USE_BOOST_ASIO` | `ON` | Use Boost.Asio; set to `OFF` for standalone Asio |
| `ASIOICE_USE_OPENSSL` | `OFF` | Enable OpenSSL (auto-enabled by DTLS/SCTP) |
| `ASIOICE_ENABLE_DTLS` | `OFF` | Enable DTLS transport |
| `ASIOICE_ENABLE_SCTP_OVER_DTLS` | `OFF` | Enable SCTP-over-DTLS data channels |
| `ENABLE_IO_URING` | `OFF` | Enable io_uring backend on Linux |
| `ASIOICE_TEST` | `ON` | Build test executables |

### Build Targets

- `asioice` -- static library
- `ice_test` -- ICE integration test (two agents, trickle ICE, RTP/RTCP)
- Individual unit tests: `stun_test`, `stun_client_test`, `turn_client_test`, `hash_test`, `candidate_test`, `async_queue_test`, `io_buffer_test`, `io_buffer2_test`, `on_scope_empty_test`
- Optional: `dtls_test`, `sctp_test`, `boost_fiber_test`

## Usage

### Including the Library

```cmake
add_subdirectory(path/to/asio-ice)
target_link_libraries(your_target PRIVATE asioice)
```

### Basic Example

The following snippet creates two ICE agents on the same machine, exchanges candidates directly via trickle ICE, and sends data over the nominated pair.

```cpp
#include "basic_agent.hpp"
#include "ignore.hpp"
#include "on_scope_empty.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include "asio2exec.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include "asio2exec.hpp"
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include <iostream>

using namespace asioice;

auto run_ice() -> task<void> {
    net::io_context ctx;
    asio2exec::scheduler sched{ctx};

    using Agent = basic_agent<net::ip::udp::socket>;

    agent_config config1{
        .username = "user1", .password = "pass1",
        .ice_controlling = true, .component_count = 1
    };
    agent_config config2{
        .username = "user2", .password = "pass2",
        .ice_controlling = false, .component_count = 1
    };

    Agent agent1(ctx.get_executor(), config1);
    Agent agent2(ctx.get_executor(), config2);

    agent2.set_remote_username(agent1.local_username());
    agent2.set_remote_password(agent1.local_password());
    agent1.set_remote_username(agent2.local_username());
    agent1.set_remote_password(agent2.local_password());

    exec::async_scope scope;

    // Trickle ICE: exchange candidates as they arrive
    agent1.on_local_candidates(
        [&](const candidate *c, std::size_t n) {
            if (c) {
                for (std::size_t i = 0; i < n; ++i)
                    scope.spawn(
                        agent2.add_remote_candidate(c[i]) | utils::ignore());
            } else {
                scope.spawn(
                    agent2.add_remote_candidate() | utils::ignore());
            }
        });

    agent2.on_local_candidates(
        [&](const candidate *c, std::size_t n) {
            if (c) {
                for (std::size_t i = 0; i < n; ++i)
                    scope.spawn(
                        agent1.add_remote_candidate(c[i]) | utils::ignore());
            } else {
                scope.spawn(
                    agent1.add_remote_candidate() | utils::ignore());
            }
        });

    agent2.on_data([&](io_buffer_ptr data, uint8_t component) {
        std::cout << "Component " << (int)component << ": "
                  << std::string_view{(const char *)data->data(), data->size()}
                  << '\n';
    });

    scope.spawn(stdexec::starts_on(sched, agent1.gather_candidates()));
    scope.spawn(stdexec::starts_on(sched, agent2.gather_candidates()));
    scope.spawn(stdexec::starts_on(sched, agent1.connect()));
    scope.spawn(stdexec::starts_on(sched, agent2.connect()));

    // Wait for all spawned work to complete
    co_await (on_scope_empty(scope) | stdexec::continues_on(sched));

    if (agent1.state() == agent_state_t::CONNECTED &&
        agent2.state() == agent_state_t::CONNECTED) {
        co_await agent1.sendto(net::buffer("Hello ICE!"), 1);
    }
}

int main() {
    net::io_context ctx;
    exec::start_detached(
        stdexec::starts_on(asio2exec::scheduler{ctx}, run_ice()));
    ctx.run();
}
```

### WebSocket Signaling Example

A more complex example demonstrating compatibility with Python aioice using Boost.Beast WebSocket for signaling:

```bash
# Build and run
cd example && mkdir build && cd build
cmake .. -DBoost_DIR=<path> -DSTDEXEC_DIR=<path>
make websocket_ice_example
./websocket_ice_example
```

Two peers exchange SDP offers/answers and trickle-ICE candidates over a WebSocket relay server (port 18080). Once ICE connects, application data flows over the nominated pair. See `example/websocket_ice_example.cpp` for the full source.

### Configuration

The `agent_config` structure tailors the ICE agent's behavior:

```cpp
asioice::agent_config cfg{
    .username = "alice",
    .password = "secret",
    .ice_controlling = true,
    .use_loopback = false,
    .use_ipv4 = true,
    .use_ipv6 = false,
    .transport = "udp",
    .stun_servers = {{net::ip::make_address("stun.l.google.com"), 19302}},
    .turn_servers = {{{net::ip::make_address("turn.example.com"), 3478},
                       "user",
                       "pass"}},
    .component_count = 1,                        // 2 for RTP + RTCP
    .transport_policy = asioice::transport_policy::ALL,
    .trickle_ice = true,
    .max_pending_check_count = 100,
    .connectivity_check_timeout = std::chrono::milliseconds(5000),
    .connectivity_check_interval = std::chrono::milliseconds(20),
    .keepalive_interval = std::chrono::milliseconds(15000)
};
```

## Architecture

### ICE State Machine

```
INIT --> GATHERING --> CONNECTING --> CONNECTED
  |         |              |              |
  +---------+--------------+-----------> CLOSED
              (close() from any state)
```

- **INIT** -- agent created, no operations started
- **GATHERING** -- collecting host, server-reflexive, and relayed candidates
- **CONNECTING** -- performing connectivity checks on candidate pairs
- **CONNECTED** -- all components have nominated pairs, data can flow
- **CLOSED** -- resources released

### Candidate Types

| Type | Enum | Obtained from |
|------|------|---------------|
| host | `candidate_type::host` | Local network interfaces |
| srflx | `candidate_type::srflx` | STUN Binding response |
| prflx | `candidate_type::prflx` | Inbound connectivity check from unknown remote |
| relay | `candidate_type::relay` | TURN Allocate response |

### Transport Layers

```
Application Data
      |
 on_data() callback
      |
 STUN demux (stun_receiver)
      |
 +----+----+----+
 |    |    |    |
UDP  TURN DTLS  SCTP
(socket) (relay) (encrypted) (data channels)
      |
 any_transport (type-erased)
```

## Testing

After building, run test executables from the build directory:

```bash
cd clang-build
./stun_test            # STUN message encoding/decoding
./stun_client_test     # STUN Binding request against a real server
./turn_client_test     # TURN allocation, channel binding, data relay
./hash_test            # MD5, SHA1, SHA256, SHA512, HMAC
./async_queue_test     # async_queue performance benchmarks
./candidate_test       # SDP candidate parsing
./ice_test             # Full ICE integration (two agents, trickle ICE)
./dtls_test            # DTLS handshake, SRTP key export (if enabled)
./sctp_test            # SCTP data channel ping-pong (if enabled)
```

Tests use plain C++ functions that throw `std::runtime_error` on failure. No external test framework is required.

## Code Style

The project follows a consistent C++ style enforced by `.clang-format` (80-column limit, 4-space indentation). Types and functions use `snake_case`, private members are prefixed with `_`. Error handling uses exceptions for unrecoverable errors and `std::error_code` for I/O operations. Coroutines (via `asioice::task<T>`) and stdexec senders are used for all asynchronous operations.

```bash
find src include -name "*.cpp" -o -name "*.hpp" -o -name "*.ipp" | xargs clang-format -i
```

## Roadmap

### Implemented

- ICE state machine (INIT, GATHERING, CONNECTING, CONNECTED, CLOSED)
- Candidate gathering (host, srflx, relay, prflx)
- Connectivity checks with triggered checks and pair priority sorting
- Aggressive and regular nomination (USE-CANDIDATE)
- Controlling/controlled role negotiation with tie-breaker resolution
- STUN message handling (HMAC-SHA-256 integrity, fingerprints)
- TURN client (allocate, refresh, permissions, channels, nonce cookies)
- DTLS transport with SRTP key material export
- Trickle ICE (incremental candidate exchange)
- Keepalive on nominated pairs

### Planned

- TCP candidate support (active, passive, simultaneous-open)
- Full ICE restart procedures
- ICE-Lite mode
- mDNS candidates
- Performance optimizations (reduced allocations, improved coroutine efficiency)
- NAT behavior discovery

## References

- [RFC 8445 -- Interactive Connectivity Establishment (ICE)](https://tools.ietf.org/html/rfc8445)
- [RFC 8489 -- Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc8489)
- [RFC 8656 -- Traversal Using Relays around NAT (TURN)](https://tools.ietf.org/html/rfc8656)
- [P2300 -- Senders and Receivers (stdexec)](https://github.com/NVIDIA/stdexec)
- [Boost.Asio](https://www.boost.org/doc/libs/release/libs/asio/)
- [OpenSSL](https://www.openssl.org/)

## License

asio-ice is released under the **MIT License**. See [LICENSE](LICENSE) for details.

## Contributing

Bug reports, feature suggestions, and pull requests are welcome. Please ensure your code adheres to the existing style and passes all tests.
