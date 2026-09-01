#pragma once

#include <stdexec/execution.hpp>

namespace asioice::utils {

namespace __with_allocator_detail {

template <class Alloc> struct sender {
    using sender_concept = stdexec::sender_tag;
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(Alloc)>;

    template <class R> auto connect(R &&r) && {
        const auto &env = stdexec::get_env(r);
        if constexpr (requires {
                          stdexec::get_allocator(env);
                          Alloc(stdexec::get_allocator(env));
                      }) {
            return stdexec::connect(stdexec::get_allocator() |
                                        stdexec::then([this](auto a) {
                                            return Alloc(std::move(a));
                                        }),
                                    std::forward<R>(r));
        } else {
            return stdexec::connect(stdexec::just(std::move(alloc)),
                                    std::forward<R>(r));
        }
    }

    Alloc alloc;
};

template <class Alloc> sender(Alloc &&) -> sender<std::decay_t<Alloc>>;

} // namespace __with_allocator_detail

template <class F, class DefaultAlloc>
    requires(std::invocable<F, DefaultAlloc> &&
             stdexec::sender<std::invoke_result_t<F, DefaultAlloc>>)
inline auto with_allocator(F &&f, DefaultAlloc &&alloc) {
    return __with_allocator_detail::sender{std::forward<DefaultAlloc>(alloc)} |
           stdexec::let_value([f = std::forward<F>(f)](const auto &a) mutable {
               return stdexec::write_env(
                   std::move(f)(a), stdexec::prop{stdexec::get_allocator, a});
           });
}

} // namespace asioice::utils