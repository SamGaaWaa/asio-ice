#pragma once

#include <exec/when_any.hpp>
#include <stdexec/execution.hpp>

namespace ice::utils {

template <stdexec::sender Sender, stdexec::sender... Trigger>
constexpr stdexec::sender auto stop_when(Sender &&snd, Trigger &&...trigger) {
    struct void_t {};
    auto trigger_stop = []<class S>(S &&s) noexcept {
        return std::forward<S>(s) | stdexec::let_value([](auto &...) noexcept {
                   return stdexec::just_stopped();
               });
    };
    return exec::when_any(std::forward<Sender>(snd),
                          trigger_stop(std::forward<Trigger>(trigger))...) |
           stdexec::then([]<class... Args>(Args &&...results) {
               constexpr auto args_n = sizeof...(Args);
               if constexpr (args_n == 0) {
                   return void_t{};
               } else if constexpr (args_n == 1) {
                   return std::get<0>(
                       std::make_tuple(std::forward<Args>(results)...));
               } else {
                   return std::make_tuple(std::forward<Args>(results)...);
               }
           }) |
           stdexec::stopped_as_optional();
}

} // namespace ice::utils
