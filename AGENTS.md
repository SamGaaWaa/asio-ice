# Agent Guidelines for asio-ice

## Project Overview

asio-ice is an ICE (RFC 8445) implementation in C++23 using Boost.Asio, OpenSSL, and [stdexec](https://github.com/NVIDIA/stdexec) for sender/receiver-based structured concurrency.

## Build Commands

**Prerequisites**: CMake 3.22+, Boost 1.89+, OpenSSL 3.0+ (optional, for DTLS), Clang 20+ / GCC 13+ / MSVC 19.34+, and `STDEXEC_DIR` pointing to stdexec's `include/` tree.

**IMPORTANT**: Every build script hardcodes personal paths (`/home/sam/opensource/...`, `C:\Boost\...`, etc.). You must edit `Boost_DIR`, `STDEXEC_DIR`, and `OPENSSL_ROOT_DIR` per machine before running them.

### Build scripts
- `./debug-build.sh` — Clang debug, address sanitizer, output `clang-build/`
- `./release-build.sh` — Clang release (`-O3`)
- `./gcc-debug-build.sh`, `./gcc-release-build.sh` — output `gcc-build/`
- `./msvc-debug-build.bat`, `./mingw-debug-build.bat` — Windows

### Manual CMake
```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DASIOICE_USE_BOOST_ASIO=ON \
         -DBoost_DIR=<path>/lib/cmake/Boost-1.89.0 \
         -DSTDEXEC_DIR=<path>/stdexec/include
make -j$(nproc)
```

### Build targets
- `asioice` — static library
- `ice_test` — full ICE integration test
- `stun_test`, `candidate_test`, `hash_test`, `turn_client_test`, `async_queue_test`, `io_buffer_test`, `io_buffer2_test`, `on_scope_empty_test`
- Optional (with `-DASIOICE_ENABLE_DTLS=ON`): `dtls_test`
- Optional (with `-DASIOICE_ENABLE_SCTP_OVER_DTLS=ON`): `sctp_test`, `boost_fiber_test`

### CMake options
| Option | Default | Description |
|--------|---------|-------------|
| `ASIOICE_USE_BOOST_ASIO` | `ON` | Use Boost.Asio; `OFF` for standalone Asio |
| `ASIOICE_USE_OPENSSL` | `OFF` | Auto-enabled by DTLS/SCTP |
| `ASIOICE_ENABLE_DTLS` | `OFF` | Enables DTLS transport |
| `ASIOICE_ENABLE_SCTP_OVER_DTLS` | `OFF` | Enables SCTP-over-DTLS + submodule build |
| `ENABLE_IO_URING` | `OFF` | io_uring backend (Linux only) |
| `ASIOICE_TEST` | `ON` | Build tests |

## Test Commands

Tests are standalone executables (no framework). Each `src/*_test.cpp` contains a `main()` and plain functions that throw `std::runtime_error` on failure.

```bash
cd clang-build
./hash_test          # run one test
# Run all: execute each *_test executable in the build directory
```

## Code Style & Conventions

### Namespaces
- **Primary namespace**: `asioice` (NOT `ice`)
- **Asio alias**: `namespace net = boost::asio;` (or `asio`) — defined *inside* `namespace asioice` in each header that needs it (not at global scope or in a shared header)
- Sub-namespaces: `asioice::stun`, `asioice::turn`, `asioice::hash`, `asioice::utils`, `asioice::fiber`, `asioice::ssl`, `asioice::impl`

### Naming
- **Types** (structs, classes, enums): `snake_case` — e.g. `agent_base`, `candidate_pair`, `agent_config`
- **Functions/variables**: `snake_case`
- **Private members**: underscore prefix `_val`, `_impl`, `_data`
- **Constants/macros**: `UPPER_SNAKE_CASE`
- **Template parameters**: short identifiers — `T`, `Sock`, `Func`, `Key`, `Rng`, `BufferSequence`, etc.

### Formatting
- `.clang-format` enforces 80-column limit, 4-space indent, right-aligned pointers
- `SortIncludes: Never` — includes order is **intentional**; never reorder or auto-sort them
- Format command: `find src include -name "*.cpp" -o -name "*.hpp" -o -name "*.ipp" | xargs clang-format -i`

### Include order (preserve, do not reorder)
1. Corresponding header (for `.cpp` files)
2. Project headers (`"config.hpp"`, `"address.hpp"`, etc.)
3. System/Boost headers
4. Conditional Boost.Asio vs standalone Asio includes using `#if ASIOICE_USE_BOOST_ASIO`

### Error handling
- Unrecoverable errors: `throw std::runtime_error("message")`
- Recoverable I/O errors: `std::error_code`
- Mark functions `noexcept` when safe (getters, move constructors)

## Project-Specific Patterns & Gotchas

### config.hpp is generated — do not edit directly
`include/asioice/config.hpp` is generated from `include/asioice/config.hpp.in` via CMake's `configure_file()`. The `.gitignore` entry (`include/config.hpp`) has a path mismatch; `config.hpp` is currently tracked but should not be hand-edited. Always edit `config.hpp.in` for configuration changes and re-run cmake.

### Key macros
- `ASIOICE_USE_BOOST_ASIO` — 1 for Boost.Asio, 0 for standalone Asio
- `ASIOICE_ENABLE_IO_URING` — 1 for io_uring (Linux only; CMake option is `ENABLE_IO_URING` without the prefix)
- `ICE_DEBUG` — 1 in debug builds (`#ifndef NDEBUG`), 0 in release

### asio2exec bridge
The `asio2exec.hpp` header (vendored in `third_party/`) bridges Asio completion tokens to stdexec senders. When using Boost.Asio, you **must** define `ASIO_TO_EXEC_USE_BOOST` **before** including it:
```cpp
#define ASIO_TO_EXEC_USE_BOOST 1
#include <asio2exec.hpp>
```

### Boost linkage
CMake sets `Boost_USE_STATIC_LIBS ON` and links `Boost::boost` (not individual components). The `Boost::json` and `Boost::context` libraries must be available.

### `.ipp` files
Template implementation files use `.ipp` extension (not `.inl`). Found in `src/ssl/` and `src/impl/`.

### Submodule
`exsctp/dcsctp` is a git submodule (https://github.com/samgaawaa/dcsctp). It is only built when `ASIOICE_ENABLE_SCTP_OVER_DTLS=ON`.

### Coroutine type
`asioice::task<T>` is an alias for `exec::basic_task<T, exec::__task::inline_task_context<T>>` from stdexec.

### When adding files
- New `.cpp` source: add to `ICE_SRC_FILES` in `CMakeLists.txt`
- New test: add to `TEST_SOURCES` glob in `CMakeLists.txt`
- New config macro: edit `include/asioice/config.hpp.in`, then re-run cmake

## References
- `.clang-format` — formatting rules
- `CMakeLists.txt` — build configuration and source file registration
- `README.md` — API overview and usage examples
