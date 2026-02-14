#pragma once

#include <stdexec/execution.hpp>

namespace ice::utils {

template <stdexec::sender S, class ...Data>
inline void detached_with_data(S&& s, Data ...data) {
    stdexec::start_detached(
        stdexec::just(std::move(data)...) |
        stdexec::let_value([_s = std::forward<S>(s)](auto& ...)mutable {
            return std::move(_s);
        })
    );
}

} // namespace ice::utils