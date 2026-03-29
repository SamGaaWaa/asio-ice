#pragma once

#include "config.hpp"

#include <variant>
#include <utility>

#include <stdexec/execution.hpp>
#include <exec/variant_sender.hpp>

#include "task.hpp"

namespace ice::utils {

template <class Ret, class... Args> struct async_function;

template <class Ret, class... Args> struct async_function<Ret(Args...)> {
    async_function() = default;

    template <class Func> explicit async_function(Func &&f) {
        if constexpr (stdexec::sender<std::invoke_result_t<Func, Args...>>) {
            _func.template emplace<1>(
                wrap<std::decay_t<Func>>{std::forward<Func>(f)});
        } else {
            _func.template emplace<0>(std::forward<Func>(f));
        }
    }

    async_function(const async_function &) = default;
    async_function(async_function &&) = default;
    async_function &operator=(const async_function &) = default;
    async_function &operator=(async_function &&) = default;

    template <class Func> async_function &operator=(Func &&f) {
        if constexpr (stdexec::sender<std::invoke_result_t<Func, Args...>>) {
            _func.template emplace<1>(
                wrap<std::decay_t<Func>>{std::forward<Func>(f)});
        } else {
            _func.template emplace<0>(std::forward<Func>(f));
        }
        return *this;
    }

    async_function &operator=(std::nullptr_t) noexcept {
        std::visit([](auto &f) { f = nullptr; }, _func);
        return *this;
    }

    operator bool() const noexcept {
        return std::visit([](const auto &f) -> bool { return !!f; }, _func);
    }

    bool is_async() const noexcept {
        return _func.index() == 1 && std::get<1>(_func) != nullptr;
    }

    bool is_sync() const noexcept {
        return _func.index() == 0 && std::get<0>(_func) != nullptr;
    }

    template <class... Args1> Ret invoke_sync(Args1 &&...args) {
        return std::get<0>(_func)(std::forward<Args1>(args)...);
    }

    template <class... Args1> ice::task<Ret> invoke_async(Args1 &&...args) {
        return std::get<1>(_func)(std::forward<Args1>(args)...);
    }

    template <class... Args1> auto invoke(Args1 &&...args) {
        using sync_sender_t = std::decay_t<decltype(stdexec::just(
            invoke_sync(std::forward<Args1>(args)...)))>;
        using return_type = exec::variant_sender<sync_sender_t, ice::task<Ret>>;
        if (_func.index() == 0)
            return return_type{
                stdexec::just(invoke_sync(std::forward<Args1>(args)...))};
        return return_type{invoke_async(std::forward<Args1>(args)...)};
    }

    template <class... Args1> auto operator()(Args1 &&...args) {
        return invoke(std::forward<Args1>(args)...);
    }

    void reset() noexcept { *this = nullptr; }

    bool operator==(std::nullptr_t) const noexcept { return (bool)(*this); }

  private:
    template <class SenderFunc> struct wrap {
        SenderFunc func;
        ice::task<Ret> operator()(Args... args) {
            co_return co_await func(std::move(args)...);
        }
    };

    template <class SenderFunc>
        requires std::is_same_v<std::invoke_result_t<SenderFunc, Args...>,
                                ice::task<Ret>>
    struct wrap<SenderFunc> {
        SenderFunc func;
        template <class... Args1> ice::task<Ret> operator()(Args1 &&...args) {
            return func(std::forward<Args1>(args)...);
        }
    };

    std::variant<std::function<Ret(Args...)>,
                 std::function<ice::task<Ret>(Args...)>>
        _func;
};

template <class... Args> struct async_function<void(Args...)> {
    async_function() = default;

    template <class Func> explicit async_function(Func &&f) {
        if constexpr (stdexec::sender<std::invoke_result_t<Func, Args...>>) {
            _func.template emplace<1>(
                wrap<std::decay_t<Func>>{std::forward<Func>(f)});
        } else {
            _func.template emplace<0>(std::forward<Func>(f));
        }
    }

    async_function(const async_function &) = default;
    async_function(async_function &&) = default;
    async_function &operator=(const async_function &) = default;
    async_function &operator=(async_function &&) = default;

    template <class Func> async_function &operator=(Func &&f) {
        if constexpr (stdexec::sender<std::invoke_result_t<Func, Args...>>) {
            _func.template emplace<1>(
                wrap<std::decay_t<Func>>{std::forward<Func>(f)});
        } else {
            _func.template emplace<0>(std::forward<Func>(f));
        }
        return *this;
    }

    async_function &operator=(std::nullptr_t) noexcept {
        std::visit([](auto &f) { f = nullptr; }, _func);
        return *this;
    }

    operator bool() const noexcept {
        return std::visit([](const auto &f) -> bool { return !!f; }, _func);
    }

    bool is_async() const noexcept {
        return _func.index() == 1 && std::get<1>(_func) != nullptr;
    }

    bool is_sync() const noexcept {
        return _func.index() == 0 && std::get<0>(_func) != nullptr;
    }

    template <class... Args1> void invoke_sync(Args1 &&...args) {
        std::get<0>(_func)(std::forward<Args1>(args)...);
    }

    template <class... Args1> ice::task<void> invoke_async(Args1 &&...args) {
        return std::get<1>(_func)(std::forward<Args1>(args)...);
    }

    template <class... Args1> auto invoke(Args1 &&...args) {
        using sync_sender_t = std::decay_t<decltype(stdexec::just())>;
        using return_type =
            exec::variant_sender<sync_sender_t, ice::task<void>>;
        if (_func.index() == 0) {
            invoke_sync(std::forward<Args1>(args)...);
            return return_type{stdexec::just()};
        }
        return return_type{invoke_async(std::forward<Args1>(args)...)};
    }

    template <class... Args1> auto operator()(Args1 &&...args) {
        return invoke(std::forward<Args1>(args)...);
    }

    void reset() noexcept { *this = nullptr; }

    bool operator==(std::nullptr_t) const noexcept { return (bool)(*this); }

  private:
    template <class SenderFunc> struct wrap {
        SenderFunc func;
        ice::task<void> operator()(Args... args) {
            co_await func(std::move(args)...);
        }
    };

    template <class SenderFunc>
        requires std::is_same_v<std::invoke_result_t<SenderFunc, Args...>,
                                ice::task<void>>
    struct wrap<SenderFunc> {
        SenderFunc func;
        template <class... Args1> ice::task<void> operator()(Args1 &&...args) {
            return func(std::forward<Args1>(args)...);
        }
    };

    std::variant<std::function<void(Args...)>,
                 std::function<ice::task<void>(Args...)>>
        _func;
};

} // namespace ice::utils