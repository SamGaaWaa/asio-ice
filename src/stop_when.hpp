#pragma once

#include <exec/when_any.hpp>
#include <stdexec/execution.hpp>

namespace ice::utils {

constexpr stdexec::sender auto stop_when(stdexec::sender auto &&snd,
                                         stdexec::sender auto &&trigger) {
    return exec::when_any(std::move(snd),
                          std::move(trigger) |
                              stdexec::let_value([](auto &...) noexcept {
                                  return stdexec::just_stopped();
                              })) |
           stdexec::then([]<class... Args>(Args &&...results) {
               constexpr auto args_n = sizeof...(Args);
               if constexpr (args_n == 0) {
                   return;
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
