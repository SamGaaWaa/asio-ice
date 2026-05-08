#pragma once

#include <stdexec/execution.hpp>

namespace exsctp::utils {

inline auto ignore() noexcept {
    return stdexec::then([](auto &&...) {});
}

template <stdexec::sender S> inline auto ignore(S &&s) noexcept {
    return stdexec::then(std::forward<S>(s), [](auto &&...) {});
}

} // namespace exsctp::utils