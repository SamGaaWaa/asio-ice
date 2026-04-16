#pragma once

#include "fiber/sender.hpp"

#include <optional>

namespace asioice::fiber {

namespace __fiber_detail {

template <stdexec::scheduler S> struct job_state {
    job_state() = default;
    job_state(const job_state &) = delete;
    job_state &operator=(const job_state &) = delete;
    job_state(job_state &&) = delete;
    job_state &operator=(job_state &&) = delete;

    struct resume_sender {
        using sender_concept = stdexec::sender_t;
        using completion_signatures =
            stdexec::completion_signatures<stdexec::set_value_t()>;

        job_state *state;

        template <stdexec::receiver R> struct op_t {
            R r;
            job_state *state;
            void start() & noexcept {
                auto job = state->job;
                auto wait_ctx = state->wait_ctx;
                auto ret = state->ret;

                // Destroy the operation state before resuming fiber
                stdexec::set_value(std::move(r));

                ::ASYNC_start_job(job, wait_ctx, ret, nullptr, nullptr, 0);
            }
        };

        template <stdexec::receiver R> auto connect(R &&r) && {
            return op_t<std::decay_t<R>>{std::forward<R>(r), state};
        }
    };

    struct resume_receiver {
        using receiver_concept = stdexec::receiver_t;
        void (*destroy_state)(void *) = nullptr;
        void *state = nullptr;
        void set_value() noexcept { destroy_state(state); }
        void set_error(auto) noexcept { destroy_state(state); }
        void set_stopped() noexcept { destroy_state(state); }
    };

    stdexec::operation_state auto resume_op(void (*destroy_state)(void *),
                                            void *state) {
        return stdexec::connect(stdexec::starts_on(*sched, resume_sender{this}),
                                resume_receiver{destroy_state, state});
    }

    ASYNC_JOB **job = nullptr;
    ASYNC_WAIT_CTX *wait_ctx = nullptr;
    int *ret;
    S *sched = nullptr;
};

template <class _Fn>
    requires std::is_nothrow_move_constructible_v<_Fn>
struct __conv {
    _Fn __fn_;
    using __t = std::invoke_result_t<_Fn>;

    operator __t() && noexcept(std::is_nothrow_invocable_v<_Fn>) {
        return ((_Fn &&)__fn_)();
    }

    __t operator()() && noexcept(std::is_nothrow_invocable_v<_Fn>) {
        return ((_Fn &&)__fn_)();
    }
};

template <class _Fn> __conv(_Fn) -> __conv<_Fn>;

template <stdexec::scheduler S> struct resume_operation {
    using operation_type =
        std::decay_t<decltype(std::declval<job_state<S>>().resume_op(nullptr,
                                                                     nullptr))>;

    resume_operation(ASYNC_JOB **job1, ASYNC_WAIT_CTX *wait_ctx1, int *ret,
                     S *sched) noexcept {
        _job_state.job = job1;
        _job_state.wait_ctx = wait_ctx1;
        _job_state.ret = ret;
        _job_state.sched = sched;
    }

    void resume() {
        auto construct_op = [this] {
            return this->_job_state.resume_op(
                [](void *self) noexcept {
                    static_cast<resume_operation *>(self)->destroy_op();
                },
                this);
        };
        _op.emplace(__conv{construct_op});
        stdexec::start(*_op);
    }

    void destroy_op() noexcept { _op.reset(); }

  private:
    job_state<S> _job_state;
    std::optional<operation_type> _op;
};

struct wait_ctx_ptr {
    wait_ctx_ptr() : _ctx(::ASYNC_WAIT_CTX_new()) {
        if (!_ctx)
            throw std::bad_alloc();
    }

    wait_ctx_ptr(const wait_ctx_ptr &) = delete;
    wait_ctx_ptr &operator=(const wait_ctx_ptr &) = delete;

    wait_ctx_ptr(wait_ctx_ptr &&other) noexcept
        : _ctx(std::exchange(other._ctx, nullptr)) {}

    wait_ctx_ptr &operator=(wait_ctx_ptr &&other) noexcept {
        if (this != &other) {
            if (_ctx)
                ::ASYNC_WAIT_CTX_free(_ctx);
            _ctx = std::exchange(other._ctx, nullptr);
        }
        return *this;
    }

    ~wait_ctx_ptr() {
        if (_ctx)
            ::ASYNC_WAIT_CTX_free(_ctx);
    }

    ASYNC_WAIT_CTX *get() noexcept { return _ctx; }

  private:
    ASYNC_WAIT_CTX *_ctx;
};

} // namespace __fiber_detail

template <stdexec::scheduler Scheduler, class Func, class... Args>
inline stdexec::sender auto spawn(Scheduler sched, Func &&f, Args &&...args) {
    using namespace __fiber_detail;
    return stdexec::just(sched, static_cast<ASYNC_JOB *>(nullptr),
                         wait_ctx_ptr(), 0, std::forward<Func>(f),
                         std::forward<Args>(args)...) |
           stdexec::let_value([](auto &sched, ASYNC_JOB *&job,
                                 wait_ctx_ptr &wait_ctx, int &ret, auto &f,
                                 auto &...args) {
               return stdexec::starts_on(
                          sched,
                          fiber::sender(
                              &job, wait_ctx.get(), &ret,
                              [&] {
                                  resume_operation<Scheduler> resume_op(
                                      &job, wait_ctx.get(), &ret, &sched);
                                  int (*resume)(void *) = [](void *p) -> int {
                                      auto op = static_cast<
                                          resume_operation<Scheduler> *>(p);
                                      op->resume();
                                      return 1;
                                  };
                                  ::ASYNC_WAIT_CTX_set_callback(
                                      wait_ctx.get(), resume, &resume_op);
                                  return std::move(f)(std::move(args)...);
                              })) |
                      stdexec::continues_on(sched);
           });
}

} // namespace asioice::fiber