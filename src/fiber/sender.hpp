#pragma once

#include <openssl/async.h>
#include <stdexcept>
#include <stdexec/execution.hpp>

namespace asioice::fiber {

template <class Func, class... Args> struct sender_base {
    using completion_signatures = stdexec::completion_signatures<
        stdexec::set_value_t(std::invoke_result_t<Func, Args...>),
        stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>;
};

template <class Func, class... Args>
    requires std::same_as<std::invoke_result_t<Func, Args...>, void>
struct sender_base<Func, Args...> {
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;
};

template <class Func, class... Args> struct sender {
    using result_type = std::invoke_result_t<Func, Args...>;
    using sender_concept = stdexec::sender_t;
    using completion_signatures =
        typename sender_base<Func, Args...>::completion_signatures;

    ASYNC_JOB **job;
    ASYNC_WAIT_CTX *ctx;
    int *ret;
    Func f;
    std::tuple<Args...> args;

    template <class _F, class... _Args>
    sender(ASYNC_JOB **job1, ASYNC_WAIT_CTX *wait_ctx, int *ret1, _F &&f1,
           _Args &&...args1)
        : job(job1), ctx(wait_ctx), ret(ret1), f(std::forward<_F>(f1)),
          args(std::forward<_Args>(args1)...) {
        if (!job || *job)
            throw std::runtime_error{"!job || *job != nullptr"};
        if (!ctx)
            throw std::runtime_error{"wait_ctx == nullptr"};
        if (!ret)
            throw std::runtime_error{"ret == nullptr"};
    }

    sender(const sender &) = delete;
    sender &operator=(const sender &) = delete;

    sender(sender &&other) noexcept
        : job(std::exchange(other.job, nullptr)),
          ctx(std::exchange(other.ctx, nullptr)),
          ret(std::exchange(other.ret, nullptr)), f(std::move(other.f)),
          args(std::move(other.args)) {}

    sender &operator=(sender &&other) noexcept {
        if (this != &other) {
            job = std::exchange(other.job, nullptr);
            ctx = std::exchange(other.ctx, nullptr);
            ret = std::exchange(other.ret, nullptr);
            f = std::move(other.f);
            args = std::move(other.args);
        }
        return *this;
    }

    template <stdexec::receiver R> struct op_t {
        ASYNC_JOB **job;
        ASYNC_WAIT_CTX *ctx;
        int *ret;
        R r;
        Func f;
        std::tuple<Args...> args;

        template <stdexec::receiver _R>
        op_t(ASYNC_JOB **job1, ASYNC_WAIT_CTX *wait_ctx, int *ret1, _R &&r1,
             Func &&f1, std::tuple<Args...> &&args1)
            : job(job1), ctx(wait_ctx), ret(ret1), r(std::forward<_R>(r1)),
              f(std::move(f1)), args(std::move(args1)) {
            if (!job || *job)
                throw std::runtime_error{"!job || *job != nullptr"};
            if (!ctx)
                throw std::runtime_error{"wait_ctx == nullptr"};
            if (!ret)
                throw std::runtime_error{"ret == nullptr"};
        }

        op_t(const op_t &) = delete;
        op_t(op_t &&) = delete;
        op_t &operator=(const op_t &) = delete;
        op_t &operator=(op_t &&) = delete;

        void start() & noexcept {
            if constexpr (!stdexec::unstoppable_token<
                              stdexec::stop_token_of_t<stdexec::env_of_t<R>>>) {
                const stdexec::stoppable_token auto st =
                    stdexec::get_stop_token(stdexec::get_env(r));
                if (st.stop_requested()) {
                    stdexec::set_stopped(std::move(r));
                    return;
                }
            }
            op_t *self = this;
            switch (::ASYNC_start_job(job, ctx, ret, job_func, &self,
                                      sizeof(op_t *))) {
            case ASYNC_ERR:
                stdexec::set_error(std::move(r),
                                   std::make_exception_ptr(std::runtime_error{
                                       "ASYNC_start_job: ASYNC_ERR"}));
                return;
            case ASYNC_NO_JOBS:
                stdexec::set_error(std::move(r),
                                   std::make_exception_ptr(std::runtime_error{
                                       "ASYNC_start_job: ASYNC_NO_JOBS"}));
                return;
            }
        }

      private:
        static int job_func(void *p) noexcept {
            op_t *op = *static_cast<op_t **>(p);
            try {
                if constexpr (std::same_as<result_type, void>) {
                    std::apply(std::move(op->f), std::move(op->args));
                    stdexec::set_value(std::move(op->r));
                } else {
                    stdexec::set_value(
                        std::move(op->r),
                        std::apply(std::move(op->f), std::move(op->args)));
                }
            } catch (...) {
                stdexec::set_error(std::move(op->r), std::current_exception());
            }

            return 1;
        }
    };

    template <stdexec::receiver R> auto connect(R &&r) && {
        return op_t<std::decay_t<R>>(job, ctx, ret, std::forward<R>(r),
                                     std::move(f), std::move(args));
    }
};

template <class F, class... Args>
sender(ASYNC_JOB **, ASYNC_WAIT_CTX *, int *, F &&,
       Args &&...) -> sender<std::decay_t<F>, std::decay_t<Args>...>;

} // namespace asioice::fiber