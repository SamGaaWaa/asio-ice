#pragma once
#include "stdexec/execution.hpp"

#include <bit>
#include <cassert>
#include <concepts>
#include <coroutine>
#include <cstdlib>
#include <memory>
#include <memory_resource>
#include <new>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>
// #include <iostream>

namespace ice {

namespace __inline_task {
namespace __detail {
namespace __coro_alloc {
struct block_t {
    alignas(alignof(std::max_align_t)) char data[alignof(std::max_align_t)];

    static auto count(std::size_t size) noexcept {
        constexpr auto block_size = sizeof(block_t);
        return (size + block_size - 1) / block_size;
    }
};

template <class Alloc>
concept is_stateless = std::allocator_traits<Alloc>::is_always_equal::value &&
                       std::is_default_constructible_v<Alloc>;

class coro_alloc {
    using dealloc_fn = void (*)(void *, std::size_t) noexcept;

    static dealloc_fn *__dealloc_address(std::uintptr_t ptr,
                                         std::size_t size) noexcept {
        constexpr auto dealloc_fn_align = alignof(dealloc_fn);
        const auto aligned = (ptr + size + dealloc_fn_align - 1) /
                             dealloc_fn_align * dealloc_fn_align;
        return std::launder(reinterpret_cast<dealloc_fn *>(aligned));
    }

    template <class Alloc>
    static Alloc *__alloc_address(std::uintptr_t ptr,
                                  std::size_t size) noexcept {
        constexpr auto alloc_align = alignof(Alloc);
        const auto d_fn =
            reinterpret_cast<std::uintptr_t>(__dealloc_address(ptr, size)) +
            sizeof(dealloc_fn);
        const auto aligned =
            (d_fn + alloc_align - 1) / alloc_align * alloc_align;
        return reinterpret_cast<Alloc *>(aligned);
    }

    // template<class Alloc>
    // static auto __alloc_size(std::size_t size)noexcept{
    //     constexpr auto alloc_size = []()constexpr{
    //         if constexpr(!std::same_as<Alloc, void>){
    //             return sizeof(Alloc);
    //         }else{
    //             return 0;
    //         }
    //     }();
    //     constexpr auto alloc_align = []()constexpr{
    //         if constexpr(!std::same_as<Alloc, void>){
    //             return alignof(Alloc);
    //         }else{
    //             return 0;
    //         }
    //     }();
    //     return size + alloc_align + alignof(dealloc_fn) + alloc_size +
    //     sizeof(dealloc_fn);
    // }

    template <class Alloc>
    static std::size_t __alloc_size(std::size_t size) noexcept {
        return reinterpret_cast<std::uintptr_t>(
                   __alloc_address<Alloc>(0, size)) +
               sizeof(Alloc);
    }

    template <class Alloc>
    static void __deallocator(void *ptr, std::size_t size) noexcept {
        const auto alloc_size = __alloc_size<Alloc>(size);
        const auto block_count = block_t::count(alloc_size);

        if constexpr (is_stateless<Alloc>) {
            Alloc a;
            a.deallocate(static_cast<block_t *>(ptr), block_count);
        } else {
            Alloc *a_ptr = __alloc_address<Alloc>(
                reinterpret_cast<std::uintptr_t>(ptr), size);
            Alloc a(std::move(*a_ptr));
            a_ptr->~Alloc();
            a.deallocate(reinterpret_cast<block_t *>(ptr), block_count);
        }
    }

    template <class Alloc>
    static void *__allocate(const Alloc &a, std::size_t size) noexcept {
        using rebind_a_t = typename std::allocator_traits<
            Alloc>::template rebind_alloc<block_t>;
        using rebind_attr_t = typename std::allocator_traits<
            Alloc>::template rebind_traits<block_t>;

        static_assert(std::is_pointer_v<typename rebind_attr_t::pointer>);

        dealloc_fn d_fn = &coro_alloc::__deallocator<rebind_a_t>;
        rebind_a_t a_rebind(a);
        const auto alloc_size = __alloc_size<rebind_a_t>(size);
        const auto block_count = block_t::count(alloc_size);
        void *p = a_rebind.allocate(block_count);
        auto d_fn_ptr =
            __dealloc_address(reinterpret_cast<std::uintptr_t>(p), size);
        // std::cout << "First calculate: " << d_fn_ptr << '\n';
        {
            auto d_fn_ptr =
                __dealloc_address(reinterpret_cast<std::uintptr_t>(p), size);
            // std::cout << "Second calculate: " << d_fn_ptr << '\n';
        }
        *d_fn_ptr = d_fn;
        if constexpr (!is_stateless<rebind_a_t>) {
            auto *a_ptr = __alloc_address<rebind_a_t>(
                reinterpret_cast<std::uintptr_t>(p), size);
            ::new (a_ptr) rebind_a_t(std::move(a_rebind));
        }
        return p;
    }

  public:
    void *operator new(std::size_t size) {
        // const auto alloc_size = __alloc_size<void>(size);
        // dealloc_fn d_fn = [](void *ptr, std::size_t n){
        //     ::operator delete(ptr, __alloc_size<void>(n));
        // };
        // void *p = ::operator new(alloc_size);
        // *__dealloc_address(reinterpret_cast<std::uintptr_t>(p), size) = d_fn;
        // return p;
        return operator new(size, std::allocator_arg, std::allocator<void>{});
    }

    template <class Alloc, class... Args>
        requires std::is_nothrow_move_constructible_v<Alloc>
    void *operator new(std::size_t size, std::allocator_arg_t, const Alloc &a,
                       const Args &...args) {
        return __allocate(a, size);
    }

    template <class This, class Alloc, class... Args>
        requires std::is_nothrow_move_constructible_v<Alloc>
    void *operator new(std::size_t size, const This &, std::allocator_arg_t,
                       const Alloc &a, const Args &...args) {
        return __allocate(a, size);
    }

    void operator delete(void *ptr, std::size_t size) noexcept {
        auto d_fn_ptr =
            __dealloc_address(reinterpret_cast<std::uintptr_t>(ptr), size);
        (*d_fn_ptr)(ptr, size);
        // delete static_cast<block_t*>(ptr);
    }
};
} // namespace __coro_alloc

template <class D>
struct promise_base : public stdexec::with_awaitable_senders<D>
// , __coro_alloc::coro_alloc
{
    promise_base() noexcept = default;
    promise_base(const promise_base &) = delete;
    promise_base &operator=(const promise_base &) = delete;
    promise_base(promise_base &&) = delete;
    promise_base &operator=(promise_base &&) = delete;

    std::suspend_always initial_suspend() const noexcept { return {}; }

    struct final_awaitable {
        static constexpr bool await_ready() noexcept { return false; }
        static auto await_suspend(std::coroutine_handle<D> self) noexcept {
            return self.promise().continuation().handle();
        }
        static void await_resume() noexcept {}
    };

    final_awaitable final_suspend() noexcept { return {}; }

    void set_stop_token(stdexec::inplace_stop_token stop_token) noexcept {
        _stop_token = stop_token;
    }

    stdexec::inplace_stop_token get_token() const noexcept {
        return _stop_token;
    }

    bool stop_requested() const noexcept {
        return _stop_token.stop_requested();
    }

    bool stop_possible() const noexcept { return _stop_token.stop_possible(); }

    // auto get_allocator()const noexcept
    //     -> std::pmr::polymorphic_allocator<>
    // {
    //     return std::pmr::polymorphic_allocator<>{};
    // }

    struct env_t {
        const promise_base *promise;

        auto
        query(stdexec::get_stop_token_t) const noexcept -> stdexec::inplace_stop_token {
            return promise->get_token();
        }
    };

    env_t get_env() const noexcept {
        return {this};
    }

  private:
    stdexec::inplace_stop_token _stop_token{};
};

struct __any_stop_callback_t {
    template <class StopToken>
    __any_stop_callback_t(const StopToken &parent_token,
                          stdexec::inplace_stop_source &self) {
        if constexpr (stdexec::unstoppable_token<std::decay_t<StopToken>>) {
            return;
        } else {
            struct forward_stop_request_t {
                stdexec::inplace_stop_source *self;
                void operator()() noexcept { self->request_stop(); }
            };
            using callback_t = typename std::decay_t<
                StopToken>::template callback_type<forward_stop_request_t>;
            static_assert(alignof(callback_t) <= alignof(std::max_align_t));
            if constexpr (sizeof(callback_t) <= sizeof(_storage)) {
                _callback = reinterpret_cast<callback_t *>(&_storage);
                new (_callback)
                    callback_t(parent_token, forward_stop_request_t{&self});
            } else {
                _callback =
                    new callback_t(parent_token, forward_stop_request_t{&self});
            }
            _destroy = +[](void *callback) {
                if constexpr (sizeof(callback_t) <= sizeof(_storage)) {
                    auto *cb = reinterpret_cast<callback_t *>(callback);
                    cb->~callback_t();
                } else {
                    delete reinterpret_cast<callback_t *>(callback);
                }
            };
        }
    }

    __any_stop_callback_t(const __any_stop_callback_t &) = delete;
    __any_stop_callback_t &operator=(const __any_stop_callback_t &) = delete;
    __any_stop_callback_t(__any_stop_callback_t &&) = delete;
    __any_stop_callback_t &operator=(__any_stop_callback_t &&) = delete;

    ~__any_stop_callback_t() {
        if (_callback && _destroy) {
            _destroy(_callback);
        }
    }

  private:
    void *_callback{nullptr};
    void (*_destroy)(void *) = nullptr;
    alignas(alignof(std::max_align_t)) char _storage[128];
};

struct stop_callback_t {
    struct forward_stop_request_t {
        stdexec::inplace_stop_source *stop_source;
        void operator()() noexcept { stop_source->request_stop(); }
    };
    using callback_t = typename stdexec::inplace_stop_token::callback_type<
        forward_stop_request_t>;

    template <class StopToken>
    stop_callback_t(const StopToken &parent_token,
                    stdexec::inplace_stop_source &self_source) {
        using stop_token_type = std::decay_t<StopToken>;
        if constexpr (stdexec::unstoppable_token<stop_token_type>)
            return;
        else if constexpr (std::is_same_v<stop_token_type,
                                          stdexec::inplace_stop_token>) {
            _callback.emplace<1>(parent_token,
                                 forward_stop_request_t{&self_source});
        } else {
            _callback.emplace<2>(parent_token, self_source);
        }
    }

  private:
    std::variant<std::monostate, callback_t, __any_stop_callback_t> _callback{};
};

template <class Promise> struct task_awaitable_base {
    std::coroutine_handle<Promise> h;
    stdexec::inplace_stop_source _stop_source{};
    std::optional<stop_callback_t> _stop_callback{};

    task_awaitable_base(std::coroutine_handle<Promise> h) noexcept : h(h) {}

    task_awaitable_base(const task_awaitable_base &) = delete;
    task_awaitable_base &operator=(const task_awaitable_base &) = delete;
    task_awaitable_base(task_awaitable_base &&) = delete;
    task_awaitable_base &operator=(task_awaitable_base &&) = delete;

    ~task_awaitable_base() {
        if (h)
            h.destroy();
    }

    static bool await_ready() noexcept { return false; }

    template <class ParentPromise>
    auto await_suspend(std::coroutine_handle<ParentPromise> parent) noexcept
        -> std::coroutine_handle<> {
        h.promise().set_continuation(parent);
        if constexpr (requires {
                          stdexec::get_env(parent.promise());
                          stdexec::get_stop_token(
                              stdexec::get_env(parent.promise()));
                      } &&
                      !stdexec::unstoppable_token<stdexec::stop_token_of_t<
                          stdexec::env_of_t<ParentPromise>>>) {
            const auto &env = stdexec::get_env(parent.promise());
            const auto &token = stdexec::get_stop_token(env);
            if (token.stop_requested()) [[unlikely]] {
                if constexpr (requires {
                                  parent.promise().unhandled_stopped();
                              }) {
                    return parent.promise().unhandled_stopped();
                }
            }
            if (token.stop_possible()) {
                _stop_callback.emplace(token, _stop_source);
                h.promise().set_stop_token(_stop_source.get_token());
            }
        }
        return h;
    }
};
} // namespace __detail

template <class T> class inline_task {
  public:
    struct promise_type : __detail::promise_base<promise_type> {
        alignas(T) char result[sizeof(T)];
        std::exception_ptr error{};

        promise_type() noexcept = default;

        inline_task get_return_object() noexcept {
            return {std::coroutine_handle<promise_type>::from_promise(*this)};
        }

        void return_value(T &&res) noexcept { new (&result) T(std::move(res)); }

        void return_value(const T &res) { new (&result) T(res); }

        void unhandled_exception() noexcept {
            error = std::current_exception();
        }
    };

    struct task_awaitable : __detail::task_awaitable_base<promise_type> {
        task_awaitable(std::coroutine_handle<promise_type> h) noexcept
            : __detail::task_awaitable_base<promise_type>(h) {}

        T await_resume() {
            this->_stop_callback.reset();
            struct __guard {
                std::coroutine_handle<promise_type> *_h;
                __guard(std::coroutine_handle<promise_type> *h) noexcept
                    : _h{h} {}
                ~__guard() { std::exchange(*_h, {}).destroy(); }
            };
            __guard on_exit(&this->h);
            if (this->h.promise().error) [[unlikely]]
                std::rethrow_exception(
                    std::exchange(this->h.promise().error, nullptr));
            T res{std::move(*reinterpret_cast<T *>(&this->h.promise().result))};
            return res;
        }
    };

    inline_task(std::coroutine_handle<promise_type> h) : _h(h) {}

    inline_task(const inline_task &) = delete;
    inline_task &operator=(const inline_task &) = delete;

    inline_task(inline_task &&other) noexcept
        : _h{std::exchange(other._h, {})} {}

    inline_task &operator=(inline_task &&other) noexcept {
        if (this != &other) {
            if (_h)
                _h.destroy();
            _h = std::exchange(other._h, {});
        }
        return *this;
    }

    task_awaitable operator co_await() && noexcept {
        return {std::exchange(_h, {})};
    }

    ~inline_task() {
        if (_h) [[unlikely]]
            _h.destroy();
    }

  private:
    std::coroutine_handle<promise_type> _h;
};

template <> class inline_task<void> {
  public:
    struct promise_type : __detail::promise_base<promise_type> {
        std::exception_ptr error{};

        promise_type() noexcept = default;

        inline_task get_return_object() noexcept {
            return {std::coroutine_handle<promise_type>::from_promise(*this)};
        }

        void return_void() noexcept {}

        void unhandled_exception() noexcept {
            error = std::current_exception();
        }
    };

    struct task_awaitable : __detail::task_awaitable_base<promise_type> {
        task_awaitable(std::coroutine_handle<promise_type> h) noexcept
            : __detail::task_awaitable_base<promise_type>(h) {}

        void await_resume() {
            this->_stop_callback.reset();
            struct __guard {
                std::coroutine_handle<promise_type> *_h;
                __guard(std::coroutine_handle<promise_type> *h) noexcept
                    : _h{h} {}
                ~__guard() { std::exchange(*_h, {}).destroy(); }
            };
            __guard on_exit(&(this->h));
            if (this->h.promise().error) [[unlikely]]
                std::rethrow_exception(
                    std::exchange(this->h.promise().error, nullptr));
        }
    };

    inline_task(std::coroutine_handle<promise_type> h) : _h(h) {}

    inline_task(const inline_task &) = delete;
    inline_task &operator=(const inline_task &) = delete;

    inline_task(inline_task &&other) noexcept
        : _h{std::exchange(other._h, {})} {}

    inline_task &operator=(inline_task &&other) noexcept {
        if (this != &other) {
            if (_h)
                _h.destroy();
            _h = std::exchange(other._h, {});
        }
        return *this;
    }

    task_awaitable operator co_await() && noexcept {
        return {std::exchange(_h, {})};
    }

    ~inline_task() {
        if (_h) [[unlikely]]
            _h.destroy();
    }

  private:
    std::coroutine_handle<promise_type> _h;
};

} // namespace __inline_task

using __inline_task::inline_task;

} // namespace ice