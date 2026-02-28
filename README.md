# asio-ice

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**asio‑ice** is a C++20/23 implementation of **Interactive Connectivity Establishment (ICE)** following RFC 8445 (ICE version 2). It leverages Boost.Asio (or standalone Asio) for asynchronous networking, OpenSSL for cryptographic operations, and modern C++ coroutines for clean, efficient async code.

The library provides a full‑featured ICE agent that can gather candidates (host, server‑reflexive, relayed), perform connectivity checks, nominate pairs, and establish peer‑to‑peer connections over UDP, with optional DTLS security and TURN relay support.

## Features

* **RFC 8445 compliant** – implements the latest ICE specification (version 2) with support for trickle ICE, role switching, and candidate gathering.
* **Modern C++** – written in C++20/23, using coroutines (`co_await`/`co_return`), concepts, and standard library utilities.
* **Asio‑based** – works with both **Boost.Asio** (≥1.83) and **standalone Asio**; all I/O is asynchronous and non‑blocking.
* **Transport abstraction** – pluggable transport layer (`any_transport`) with built‑in UDP socket transport, DTLS transport (via OpenSSL), and TURN client.
* **Full candidate support** – host, server‑reflexive (STUN), and relayed (TURN) candidates; IPv4/IPv6 dual‑stack.
* **Connectivity checks** – STUN‑based checks with retransmission, pair priority sorting, triggered checks, and nomination.
* **Security** – DTLS‑SRTP support for encrypted media; STUN message integrity with HMAC‑SHA‑256.
* **Configurable** – fine‑tune ICE agent behavior through `agent_config` (STUN/TURN servers, component count, transport policy, timeouts, etc.).
* **Test suite** – comprehensive unit tests for each component (STUN, candidate, hash, async queues, etc.).
* **Cross‑platform** – builds on Linux, macOS, and Windows (MSVC, Clang‑CL, GCC).

## Dependencies

* **Compiler** with C++23 support (Clang 20+, GCC 13+, MSVC 19.34+)
* **CMake** 3.22+
* **Boost** 1.83+ (components: `json`, `context`)
* **OpenSSL** development libraries (3.0+ recommended)
* Optional: **liburing** (for io_uring support on Linux)

## Building

### Quick Start

```bash
./debug-build.sh        # Clang debug build with address sanitizer
./release-build.sh      # Clang release build (-O3)
./gcc-debug-build.sh    # GCC debug build
./gcc-release-build.sh  # GCC release build
```

The build scripts create a `clang‑build/` or `gcc‑build/` directory containing the static library `libasioice.a` and the test executables.

### Manual CMake Build

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug \
         -DASIOICE_USE_BOOST_ASIO=ON \
         -DBoost_DIR=<path_to_boost_cmake> \
         -DOPENSSL_LIB_DIR=<openssl_lib_path> \
         -DOPENSSL_INCLUDE_DIR=<openssl_include_path>
make -j$(nproc)
```

Configuration options:
* `-DASIOICE_USE_BOOST_ASIO=ON` – use Boost.Asio (default); set to `OFF` for standalone Asio.
* `-DENABLE_IO_URING=ON` – enable io_uring backend on Linux (requires liburing).
* `-DICE_TEST=ON` – build test executables (default).

### Build Targets

* `asioice` – static library
* `ice_test` – main integration test
* Individual unit tests (`*_test`) – e.g., `stun_test`, `hash_test`, `async_queue_test`

## Usage

### Including the Library

Add `asioice` to your `CMakeLists.txt`:

```cmake
find_package(asioice REQUIRED)
target_link_libraries(your_target PRIVATE asioice)
```

Or, if you built it locally:

```cmake
add_subdirectory(path/to/asio-ice)
target_link_libraries(your_target PRIVATE asioice)
```

### Basic Example

The following snippet shows how to create two ICE agents, gather candidates, exchange them (trickle ICE), and perform connectivity checks.

```cpp
#include "ice.hpp"
#include "agent_config.hpp"
#include "ice_impl.hpp"

#include <boost/asio/io_context.hpp>

using namespace ice;
namespace net = boost::asio;  // or `asio` if using standalone Asio

int main() {
    net::io_context ctx;

    agent_config config1{
        .username = "user1",
        .password = "pass1",
        .ice_controlling = true,
        .component_count = 1,
        .transport_policy = transport_policy::ALL
    };

    auto agent1 = std::make_shared<impl::agent_datagram_impl<net::ip::udp::socket>>(ctx, config1);

    agent_config config2{
        .username = "user2",
        .password = "pass2",
        .ice_controlling = false,
        .component_count = 1,
        .transport_policy = transport_policy::ALL
    };

    auto agent2 = std::make_shared<impl::agent_datagram_impl<net::ip::udp::socket>>(ctx, config2);

    // Set remote credentials (normally exchanged via signaling)
    agent2->set_remote_username(config1.username);
    agent2->set_remote_password(config1.password);
    agent1->set_remote_username(config2.username);
    agent1->set_remote_password(config2.password);

    // Trickle ICE: gather candidates and send them to the peer as they arrive
    agent1->on_local_candidates([agent2](const candidate* c, std::size_t n) -> ice::task<void> {
        for (std::size_t i = 0; i < n; ++i) {
            co_await agent2->add_remote_candidate(c[i]);
        }
    });

    agent2->on_local_candidates([agent1](const candidate* c, std::size_t n) -> ice::task<void> {
        for (std::size_t i = 0; i < n; ++i) {
            co_await agent1->add_remote_candidate(c[i]);
        }
    });

    // Start gathering and connecting
    exec::async_scope scope;
    asio2exec::scheduler sched{ctx};

    scope.spawn(stdexec::starts_on(sched, agent1->gather_candidates()));
    scope.spawn(stdexec::starts_on(sched, agent2->gather_candidates()));
    scope.spawn(stdexec::starts_on(sched, agent1->connect()));
    scope.spawn(stdexec::starts_on(sched, agent2->connect()));

    // Run the I/O context
    ctx.run();

    // Check connection state
    if (agent1->state() == impl::agent_state_t::CONNECTED &&
        agent2->state() == impl::agent_state_t::CONNECTED) {
        std::cout << "ICE connection established successfully.\n";
    }

    return 0;
}
```

### Configuration

The `agent_config` structure allows you to tailor the ICE agent’s behavior:

```cpp
ice::agent_config cfg{
    .username = "alice",
    .password = "secret",
    .ice_controlling = true,
    .use_ipv4 = true,
    .use_ipv6 = false,
    .stun_servers = {{net::ip::make_address("stun.l.google.com"), 19302}},
    .turn_servers = {{
        {net::ip::make_address("turn.example.com"), 3478},
        "user",
        "pass"
    }},
    .component_count = 2,                    // RTP and RTCP components
    .transport_policy = ice::transport_policy::ALL,
    .trickle_ice = true,
    .connectivity_check_timeout = std::chrono::seconds(5)
};
```

## Testing

After building, run the test executables:

```bash
cd clang-build
./stun_test
./hash_test
./async_queue_test
./ice_test          # integration test with two agents
```

The test suite verifies STUN encoding/decoding, candidate pairing, hash functions, async primitives, and the full ICE connectivity check sequence.

## Code Style

The project follows a consistent C++ style enforced by `.clang‑format` (80‑column limit, 4‑space indentation). Namespaces are `snake_case` for types and functions, private members are prefixed with `_`. Error handling uses exceptions for unrecoverable errors and `std::error_code` for I/O operations. Coroutines are used for all asynchronous operations.

To format the code:

```bash
find src include -name "*.cpp" -o -name "*.hpp" -o -name "*.ipp" | xargs clang-format -i
```

## Roadmap

### ✅ Fully Implemented Core Features
- **ICE State Machine** – `INIT`, `GATHERING`, `CONNECTING`, `CONNECTED`, `CLOSED` states
- **Candidate Gathering** – Host, server‑reflexive (STUN), relayed (TURN), peer‑reflexive candidates
- **Connectivity Checks** – Full check‑list algorithm with triggered checks and pair priority sorting
- **Nomination** – Both aggressive (USE‑CANDIDATE) and regular nomination modes
- **Role Control** – Controlling/controlled roles with tie‑breaker and role‑conflict resolution
- **STUN/TURN Integration** – Complete STUN message handling and TURN client with allocations/permissions
- **Security** – STUN message integrity (HMAC‑SHA‑256) and DTLS‑SRTP support

### ⚠️ Partially Implemented / Missing Features
| Feature | Status | RFC Section | Priority |
|---------|--------|-------------|----------|
| TCP candidates | Not implemented | 5.1.1 | High |
| ICE keepalives | Missing after connection | 11 | High |
| ICE‑Lite mode | Partially implemented | 7.3.2 | Medium |
| ICE restart | Not implemented | 9 | Medium |
| mDNS candidates | Marked as TODO | 5.1.1 | Low |
| NAT behavior discovery | Not implemented | — | Low |
| Packet fragmentation/combining | Not supported | — | Low |

### 🔧 Known Issues & Improvements
- **Candidate‑pair priority calculation** – Potential overflow on 32‑bit systems (`src/candidate_pair.cpp:49‑54`)
- **Early‑check handling** – Busy‑waiting for state changes (`src/impl/ice_impl.ipp:1218‑1228`)
- **Excessive debug output** – `ICE_IN_DEBUG` macros may impact performance

### 🎯 Planned Enhancements
1. **TCP candidate support** – Full TCP (active/passive/simultaneous‑open) candidate gathering
2. **ICE keepalive mechanism** – Periodic STUN Binding requests to maintain NAT bindings
3. **Complete ICE‑Lite implementation** – Support for lightweight ICE endpoints
4. **ICE restart procedures** – Clean restart for network changes or renegotiation
5. **Performance optimizations** – Reduce memory allocations, improve coroutine efficiency
6. **Better error recovery** – Enhanced fault tolerance and fallback strategies

## License

asio‑ice is released under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## References

* [RFC 8445 – Interactive Connectivity Establishment (ICE)](https://tools.ietf.org/html/rfc8445)
* [RFC 8489 – STUN (Session Traversal Utilities for NAT)](https://tools.ietf.org/html/rfc8489)
* [RFC 8656 – Traversal Using Relays around NAT (TURN)](https://tools.ietf.org/html/rfc8656)
* [Boost.Asio](https://www.boost.org/doc/libs/release/libs/asio/)
* [OpenSSL](https://www.openssl.org/)

## Contributing

Bug reports, feature suggestions, and pull requests are welcome. Please ensure your code adheres to the existing style and passes all tests.
