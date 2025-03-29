#pragma once

#include <atomic>
#include <mutex>
#include <openssl/async.h>
#include <utility>

namespace ice::fiber {

struct condition_variable {
    condition_variable() = default;

    condition_variable(const condition_variable &) = delete;
    condition_variable &operator=(const condition_variable &) = delete;
    condition_variable(condition_variable &&) = delete;
    condition_variable &operator=(condition_variable &&) = delete;

    template <class Lock, class Pred> void wait(Lock &lock, Pred pred) {
        while (!pred()) {
            auto wait_ctx = ::ASYNC_get_wait_ctx(::ASYNC_get_current_job());
            callback_ctx ctx;
            ::ASYNC_WAIT_CTX_get_callback(wait_ctx, &ctx.resume, &ctx.args);
            _ctx.exchange(&ctx);
            lock.unlock();
            ::ASYNC_pause_job();
            lock.lock();
        }
    }

    void notify() {
        auto ctx = _ctx.exchange(nullptr);
        if (ctx)
            ctx->resume(ctx->args);
    }

  private:
    struct callback_ctx {
        int (*resume)(void *) = nullptr;
        void *args = nullptr;
    };

    std::atomic<callback_ctx *> _ctx{nullptr};
};

} // namespace ice::fiber