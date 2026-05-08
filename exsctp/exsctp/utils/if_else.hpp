#pragma once

#include <stdexec/execution.hpp>
#include <exec/variant_sender.hpp>

namespace exsctp::utils {

template <class Func>
concept sender_generator =
    (std::is_invocable_v<Func> && stdexec::sender<std::invoke_result_t<Func>>);

template <stdexec::sender Cond, sender_generator Func1, sender_generator Func2>
inline auto if_else(Cond &&cond, Func1 &&func1, Func2 &&func2) noexcept(
    std::is_nothrow_invocable_v<Func1> && std::is_nothrow_invocable_v<Func2>) {
    using result_sender_t =
        exec::variant_sender<std::decay_t<std::invoke_result_t<Func1>>,
                             std::decay_t<std::invoke_result_t<Func2>>>;
    return std::forward<Cond>(cond) |
           stdexec::let_value([f1 = std::forward<Func1>(func1),
                               f2 = std::forward<Func2>(func2)](
                                  bool cond) mutable -> result_sender_t {
               if (cond)
                   return std::move(f1)();
               return std::move(f2)();
           });
}

} // namespace exsctp::utils