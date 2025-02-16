#pragma once

#include <type_traits>

namespace ice::utils {
template <class F>
    requires std::is_nothrow_invocable_v<F> &&
             std::is_nothrow_move_constructible_v<F>
struct scope_guard {
    explicit scope_guard(F &&f) noexcept : _f{static_cast<F &&>(f)} {}

    scope_guard(const scope_guard &) = delete;
    scope_guard(scope_guard &&) = delete;

    void dismiss() noexcept { _dismissed = true; }

    ~scope_guard() {
        if (!_dismissed)
            static_cast<F &&>(_f)();
    }

  private:
    F _f;
    bool _dismissed{false};
};

template <class F> scope_guard(F) -> scope_guard<F>;
} // namespace ice::utils