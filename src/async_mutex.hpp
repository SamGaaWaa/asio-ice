#pragma once

#include "if_else.hpp"
#include "shared_promise.hpp"

#include <cassert>

namespace asioice::utils {

struct async_mutex {
    struct guard {
        guard(const guard &) = delete;
        guard(guard &&other) noexcept : _m{std::exchange(other._m, nullptr)} {}
        guard &operator=(const guard &) = delete;
        guard &operator=(guard &&other) noexcept {
            if (&other != this) {
                unlock();
                _m = std::exchange(other._m, nullptr);
            }
            return *this;
        }

        ~guard() { unlock(); }

        bool owns_lock() const noexcept { return _m != nullptr; }

        operator bool() const noexcept { return owns_lock(); }

        void unlock() noexcept {
            if (_m) {
                _m->_used = false;
                _m->_waiters.set_one_value();
            }
        }

      private:
        friend struct async_mutex;
        guard(async_mutex &m) noexcept : _m{&m} {
            assert(!_m->_used);
            _m->_used = true;
        }

        async_mutex *_m;
    };

    async_mutex() noexcept = default;

    async_mutex(const async_mutex &) = delete;
    async_mutex(async_mutex &&) = delete;
    async_mutex &operator=(const async_mutex &) = delete;
    async_mutex &operator=(async_mutex &&) = delete;

    auto lock() noexcept {
        return asioice::utils::if_else(
            stdexec::just(_used),
            [this] {
                return _waiters.get_future() |
                       stdexec::then([this] { return guard{*this}; });
            },
            [this] { return stdexec::just(guard{*this}); });
    }

    ~async_mutex() { assert(!_used); }

  private:
    bool _used{false};
    asioice::shared_promise<void> _waiters{};
};

} // namespace asioice::utils