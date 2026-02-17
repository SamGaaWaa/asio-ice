#pragma once

#include "config.hpp"
#include "shared_promise.hpp"

#include <chrono>

namespace ice::utils {

template <class T>
struct property {
    template <class ...Args>
    explicit property(Args&& ...args):
        _val(std::forward<Args>(args)...)
    {}

    property(const property& other):
        _val(other._val)
    {}

    property& operator=(const property& other) {
        return assign(other._val);
    }

    property& operator=(const T& x) {
        return assign(x);
    }

    property(property&&) = delete;
    property& operator=(property&&) = delete;

    operator const T& () const noexcept {
        return _val;
    }

    const T& get() const noexcept {
        return _val;
    }

    property& assign(T x) {
        if (x != _val) {
            _val = std::move(x);
            _update_time = std::chrono::steady_clock::now();
            _notifier.set_value();
        }
        return *this;
    }

    auto update_time() const noexcept {
        return _update_time;
    }

    auto on_change() noexcept {
        return _notifier.get_future();
    }
private:
    T _val;
    std::chrono::time_point<std::chrono::steady_clock> _update_time{};
    ice::shared_promise<void> _notifier{};
};

template <class T>
inline bool operator==(const property<T>& a, const T& b) noexcept {
    return a.get() == b;
}

template <class T>
inline bool operator==(const T& a, const property<T>& b) noexcept {
    return a == b.get();
}

template <class T>
inline auto operator<=>(const property<T>& a, const T& b) noexcept {
    return a.get() <=> b;
}

template <class T>
inline auto operator<=>(const T& a, const property<T>& b) noexcept {
    return a <=> b.get();
}

} // namespace ice::utils