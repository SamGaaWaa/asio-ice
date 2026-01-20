#pragma once

#include "config.hpp"
#include "shared_promise_v2.hpp"

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
            _notifier.set_value();
        }
        return *this;
    }

    auto on_change() noexcept {
        return _notifier.get_future();
    }
private:
    T _val;
    ice::shared_promise<void> _notifier{};
};

} // namespace ice::utils