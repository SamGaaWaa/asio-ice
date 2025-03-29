#pragma once

#include "fiber/run_loop.hpp"

namespace ice::fiber {

struct sync_wait_t {
  private:
    struct state {
        fiber::run_loop loop;
        std::exception_ptr err;
    };

    struct env {
        fiber::run_loop *loop = nullptr;

        auto query(stdexec::get_scheduler_t) const noexcept ->
            typename fiber::run_loop::__scheduler {
            return loop->get_scheduler();
        }

        auto query(stdexec::get_delegation_scheduler_t) const noexcept ->
            typename fiber::run_loop::__scheduler {
            return loop->get_scheduler();
        }
    };

    template <class Values> struct finish_receiver {
        using receiver_concept = stdexec::receiver_t;

        state *st;
        std::optional<Values> *res;

        template <class... Args>
            requires std::constructible_from<Values, Args...>
        void set_value(Args &&...args) noexcept {
            try {
                res->emplace(std::forward<Args>(args)...);
            } catch (...) {
                st->err = std::current_exception();
            }
            st->loop.finish();
        }

        template <class Error> void set_error(Error &&err) noexcept {
            if constexpr (std::is_same_v<Error, std::exception_ptr>) {
                st->err = std::forward<Error>(err);
            } else if constexpr (std::is_same_v<Error, std::error_code>) {
                st->err = std::make_exception_ptr(
                    std::system_error(std::forward<Error>(err)));
            } else {
                st->err = std::make_exception_ptr(std::forward<Error>(err));
            }
            st->loop.finish();
        }

        void set_stopped() noexcept { st->loop.finish(); }

        auto get_env() const noexcept -> env { return env{&st->loop}; }
    };

  public:
    template <stdexec::sender S> auto operator()(S &&snd) const {
        using result_type = typename decltype(stdexec::sync_wait(
            std::forward<S>(snd)))::value_type;
        state local_state{};
        std::optional<result_type> result{};

        auto op_state = stdexec::connect(
            std::forward<S>(snd),
            finish_receiver<result_type>{&local_state, &result});
        stdexec::start(op_state);

        local_state.loop.run();
        if (local_state.err) {
            std::rethrow_exception(local_state.err);
        }
        return result;
    }
};

inline constexpr sync_wait_t sync_wait{};
} // namespace ice::fiber