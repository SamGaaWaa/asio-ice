# Agent Guidelines for asio-ice

This document provides guidelines for AI agents working on the asio-ice codebase.

## Project Overview

asio-ice is an ICE (Interactive Connectivity Establishment) implementation in C++20/23. It uses Boost.Asio (or standalone Asio) for networking, OpenSSL for cryptography, and custom coroutine-based async abstractions.

## Build Commands

**Prerequisites**: CMake 3.22+, Boost 1.83+ (components: json, context), OpenSSL development libraries, compiler with C++23 support (Clang 20+, GCC 13+, MSVC 19.34+).

### Standard Build Scripts
- `./debug-build.sh` – Clang debug build with address sanitizer (output in `clang-build`)
- `./release-build.sh` – Clang release build (`-O3`, no debug symbols)
- `./gcc-debug-build.sh`, `./gcc-release-build.sh` – GCC builds
- `./msvc-debug-build.bat` – MSVC debug build (Windows, requires VS environment)

### Manual CMake Configuration
```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DASIOICE_USE_BOOST_ASIO=ON \
         -DBoost_DIR=<path_to_boost_cmake> \
         -DOPENSSL_LIB_DIR=<openssl_lib_path> \
         -DOPENSSL_INCLUDE_DIR=<openssl_include_path>
make -j$(nproc)
```
### Build Targets
- `asioice` – static library
- `ice_test` – main test executable
- Individual test executables (`*_test`) – built from `src/*_test.cpp`

## Lint/Format Commands

### Code Formatting
The project uses `.clang-format` with 80‑column limit, 4‑space indentation.

To format a single file:
```bash
clang-format -i path/to/file.cpp
```

To format all source files:
```bash
find src include -name "*.cpp" -o -name "*.hpp" -o -name "*.ipp" | xargs clang-format -i
```

### Linting
No automatic linting (clang‑tidy) is configured. Rely on compiler warnings and address sanitizer.

## Test Commands

### Running Tests
After building, test executables are in the build directory (e.g., `clang‑build/`). Each test is a standalone executable named `*_test`.

Run a single test (e.g., `hash_test`):
```bash
cd clang-build
./hash_test
```

To run all tests, execute each `*_test` executable.

### Test Structure
- Tests are plain C++ functions that throw `std::runtime_error` on failure.
- Each `*_test.cpp` file contains a `main()` function that calls the test functions.
- No external test framework is used.

### Debugging Tests
Build with `-DCMAKE_BUILD_TYPE=Debug` and address sanitizer enabled (default in `debug-build.sh`). Use `gdb` or `lldb` as needed.

## Code Style Guidelines

### General Principles
- Follow existing codebase conventions.
- Prioritize correctness, performance, and clarity.
- Use modern C++23 features where appropriate.
### Naming Conventions
- **Types (structs, classes, enums)**: `snake_case`
- **Functions and variables**: `snake_case`
- **Private member variables**: prefix with underscore (`_`)
- **Constants and macros**: `UPPER_SNAKE_CASE`
- **Template parameters**: `PascalCase`
### Includes Order
1. Corresponding header (for `.cpp` files)
2. Project headers (`"config.hpp"`, `"address.hpp"`, etc.)
3. System/Boost headers (`<vector>`, `<boost/asio.hpp>`)
4. Conditional includes based on `ASIOICE_USE_BOOST_ASIO`
### Namespaces
- Primary namespace: `ice`
- Alias `net` for `boost::asio` or `asio` (depending on config)
- Avoid `using namespace` in headers; allowed in `.cpp` files for brevity.
### Error Handling
- Use exceptions for unrecoverable errors (e.g., `throw std::runtime_error("message")`).
- Use `std::error_code` for recoverable I/O errors (common with Asio operations).
- Mark functions `noexcept` when they cannot throw (e.g., getters, move operations).
- Use `[[likely]]`/`[[unlikely]]` for branch hints where performance is critical.
### C++ Features
- Prefer `constexpr` and `consteval` where possible.
- Use coroutines (`co_await`, `co_return`) for async operations.
- Use concepts (`requires`) to constrain templates.
- Use `std::variant`, `std::optional`, `std::string_view` appropriately.
- Prefer stack allocation and RAII types; use smart pointers for ownership.
- Leverage Asio’s executors and I/O context; use custom async abstractions (`task`, `async_queue`, `shared_promise`).
- Ensure thread‑safety where required (e.g., `std::mutex`, `std::atomic`).
- Document public APIs with clear comments; follow existing comment style.

## Project‑Specific Patterns & Common Pitfalls

### Configuration
- `ASIOICE_USE_BOOST_ASIO` – 1 if using Boost.Asio, 0 for standalone Asio.
- `ASIOICE_ENABLE_IO_URING` – 1 to enable io_uring support (Linux only).
- `ICE_DEBUG` – 1 in debug builds, 0 in release.

### Transport Abstraction
- `any_transport` type‑erased transport interface.
- `dtls_transport` for DTLS‑secured communication.
- `socket_transport` for plain UDP/TCP sockets.

### ICE Concepts
- `candidate`, `candidate_pair`, `stun_transaction`, `turn_client`.
- Follow RFC 5245 semantics; refer to existing implementations.

### Common Pitfalls
- Update `config.hpp.in` when adding new configuration macros.
- Include `config.hpp` in headers that use `ASIOICE_*` macros.
- Conditionally include Boost.Asio / standalone Asio.
- Mark move constructors `noexcept`.
- Respect 80‑column limit (enforced by `.clang‑format`).

## Quick Reference

### Adding Code & Formatting
- **New source file**: Add `.cpp` to `src/`, update `CMakeLists.txt` (`ICE_SRC_FILES` or `TEST_SOURCES`), create header, follow include order, write tests in `*_test.cpp`.
- **New test**: Create `src/*_test.cpp`, implement throwing test functions, add `main()`, build and run executable.
- **Formatting**: `find src include -name "*.cpp" -o -name "*.hpp" -o -name "*.ipp" | xargs clang-format -i`

### Typical Workflow
```bash
./debug-build.sh
cd clang-build
./your_feature_test
clang-format -i ../src/your_feature.cpp
```

## References
- `.clang‑format` – formatting rules
- `CMakeLists.txt` – build configuration
- Existing source files (`src/`, `include/`) – examples
