#pragma once

#include "fiber/sender.hpp"

namespace ice::fiber {

namespace __fiber_detail {

template <stdexec::scheduler S> struct job_state {
    ASYNC_JOB **job = nullptr;
    ASYNC_WAIT_CTX *wait_ctx = nullptr;
    int *ret;
    S *sched = nullptr;
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
stdexec::sender auto spawn(Scheduler sched, Func &&f, Args &&...args) {
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
                                  job_state<Scheduler> state;
                                  state.job = &job;
                                  state.wait_ctx = wait_ctx.get();
                                  state.ret = &ret;
                                  state.sched = &sched;
                                  int (*resume)(void *) = [](void *p) -> int {
                                      auto state =
                                          static_cast<job_state<Scheduler> *>(
                                              p);
                                      stdexec::start_detached(
                                          stdexec::starts_on(
                                              *state->sched,
                                              stdexec::just() |
                                                  stdexec::then([state] {
                                                      ::ASYNC_start_job(
                                                          state->job,
                                                          state->wait_ctx,
                                                          state->ret, nullptr,
                                                          nullptr, 0);
                                                  })));
                                      return 1;
                                  };
                                  ::ASYNC_WAIT_CTX_set_callback(state.wait_ctx,
                                                                resume, &state);
                                  return std::move(f)(std::move(args)...);
                              })) |
                      stdexec::continues_on(sched);
           });
}

} // namespace ice::fiber