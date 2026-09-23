#pragma once

#include <stdexec/execution.hpp>

#include <type_traits>
#include <concepts>

namespace asioice::utils {

template <std::size_t N, class Func>
    requires(std::invocable<Func, std::size_t> &&
             stdexec::sender<std::invoke_result_t<Func, std::size_t>>)
constexpr auto when_all_range(Func &&f) {
    return [f = std::forward<Func>(f)]<size_t... Idx>(
               std::index_sequence<Idx...>) constexpr {
        return stdexec::when_all(f(Idx)...);
    }(std::make_index_sequence<N>{});
}

} // namespace asioice::utils