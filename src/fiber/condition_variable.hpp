#pragma once

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
            {
                auto wait_ctx = ::ASYNC_get_wait_ctx(::ASYNC_get_current_job());
                int (*resume)(void *) = nullptr;
                void *args = nullptr;
                ::ASYNC_WAIT_CTX_get_callback(wait_ctx, &resume, &args);
                std::lock_guard lk(_mtx);
                _resume = resume;
                _args = args;
            }
            lock.unlock();
            ::ASYNC_pause_job();
            lock.lock();
        }
    }

    void notify() {
        int (*resume)(void *) = nullptr;
        void *args = nullptr;
        {
            std::lock_guard lk(_mtx);
            std::swap(resume, _resume);
            std::swap(args, _args);
        }
        if (resume)
            resume(args);
    }

  private:
    int (*_resume)(void *) = nullptr;
    void *_args = nullptr;
    mutable std::mutex _mtx;
};

} // namespace ice::fiber