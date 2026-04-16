#pragma once

#include <stdexec/execution.hpp>
#include <exec/start_detached.hpp>

namespace asioice::utils {

template <stdexec::sender S, class... Data>
inline void detached_with_data(S &&s, Data... data) {
    exec::start_detached(
        stdexec::just(std::move(data)...) |
        stdexec::let_value([_s = std::forward<S>(s)](auto &...) mutable {
            return std::move(_s);
        }));
}

} // namespace asioice::utils