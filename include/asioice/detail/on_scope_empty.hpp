#pragma once

#include <exec/async_scope.hpp>
#include <optional>

namespace asioice::utils {

namespace __on_scope_empty_detail {

template <class StopToken> struct callback_storage {
    callback_storage(const StopToken &t, exec::async_scope &scope) {
        new (&_storage) stop_callback_t{t, on_stop_t{scope}};
    }

    callback_storage(const callback_storage &) = delete;
    callback_storage &operator=(const callback_storage &) = delete;
    callback_storage(callback_storage &&other) = delete;
    callback_storage &operator=(callback_storage &&other) = delete;

    ~callback_storage() { std::destroy_at((stop_callback_t *)&_storage); }

  private:
    struct on_stop_t {
        void operator()() noexcept { s.request_stop(); }
        exec::async_scope &s;
    };
    using stop_callback_t =
        typename StopToken::template callback_type<on_stop_t>;

    alignas(alignof(stop_callback_t)) char _storage[sizeof(stop_callback_t)];
};

struct on_empty_sender {
    using sender_concept = stdexec::sender_t;
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;

    template <class R> struct op_t {
        using stop_token_t = stdexec::stop_token_of_t<stdexec::env_of_t<R>>;
        using inner_sender_t = std::decay_t<
            decltype(std::declval<exec::async_scope &>().on_empty())>;
        using inner_op_t = std::decay_t<decltype(stdexec::connect(
            std::declval<inner_sender_t>(), std::declval<R>()))>;

        template <class _R>
        op_t(exec::async_scope &scope, _R &&r)
            : _cb_storage(stdexec::get_stop_token(stdexec::get_env(r)), scope),
              _inner_op{
                  stdexec::connect(scope.on_empty(), std::forward<_R>(r))} {}

        void start() & noexcept { stdexec::start(_inner_op); }

      private:
        callback_storage<stop_token_t> _cb_storage;
        inner_op_t _inner_op;
    };

    template <stdexec::receiver R> auto connect(R &&r) && {
        return op_t<std::decay_t<R>>(*scope, std::forward<R>(r));
    }

    exec::async_scope *scope;
};

} // namespace __on_scope_empty_detail

inline auto on_scope_empty(exec::async_scope &scope) {
    return stdexec::get_stop_token() |
           stdexec::let_value([&scope](auto token) noexcept {
               using token_t = std::decay_t<decltype(token)>;
               if constexpr (stdexec::unstoppable_token<token_t>) {
                   return scope.on_empty();
               } else {
                   return __on_scope_empty_detail::on_empty_sender(&scope);
               }
           });
}

} // namespace asioice::utils