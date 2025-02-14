#include <stdexec/execution.hpp>

#include <boost/circular_buffer.hpp>
#include <boost/intrusive/list.hpp>
#include <boost/intrusive/list_hook.hpp>

#include <coroutine>
#include <optional>
#include <limits>
#include <memory>
#include <type_traits>
#include <concepts>
#include <iostream>
#include <deque>

namespace ice {

template<class T, class C = std::deque<T>>
    requires std::is_nothrow_move_constructible_v<T>
class async_queue {
public:
    using container_type = C;

    template<bool stoppable>
    struct result {
        async_queue *self;

        auto operator co_await()&& noexcept{
            if constexpr (stoppable) {
                return read_awaitable{*self};
            } else {
                return read_awaitable_base{*self};
            }
        }
    };

    explicit async_queue(std::size_t max = std::numeric_limits<std::size_t>::max())noexcept:
        _max(max)
    {
        if constexpr (std::is_same_v<container_type, boost::circular_buffer<T>>) {
            _q.set_capacity(max);
        }
    }

    async_queue(const async_queue&) = delete;
    async_queue(async_queue&&) = delete;
    async_queue& operator=(const async_queue&) = delete;
    async_queue& operator=(async_queue&&) = delete;

    template<class _T, class OverflowHandler>
        requires std::is_invocable_v<OverflowHandler, container_type&>
    void push(_T&& t, OverflowHandler&& handler) {
        if (_closed) [[unlikely]]
            return;
        if (!_readers.empty()) {
            assert(_q.empty());
            auto& r = _readers.front();
            r.set_value(std::forward<_T>(t));
            return;
        }
        if (_q.size() == _max) [[unlikely]]
            std::forward<OverflowHandler>(handler)(_q);
        _q.push_back(std::forward<_T>(t)); // May override
    }

    template<class _T>
    void push(_T&& t) {
        push(std::forward<_T>(t), [](container_type& c)noexcept {
            c.pop_front();
        });
    }

    auto async_pop()noexcept {
        return result<false>{ this };
    }

    auto async_pop_stoppable()noexcept {
        return result<true>{ this };
    }

    void close() {
        while (!_readers.empty()) {
            auto& r = _readers.front();
            _readers.pop_front();
            r.set_stopped();
        }
        _closed = true;
    }

    std::size_t max_size()const noexcept {
        return _max;
    }

    std::size_t size()const noexcept {
        return _q.size();
    }

    bool is_open()const noexcept {
        return !_closed;
    }

    bool full()const noexcept {
        return _q.size() == _max;
    }

    bool empty()const noexcept {
        return _q.empty();
    }
private:
    struct read_awaitable_base: public boost::intrusive::list_base_hook<
        boost::intrusive::link_mode<boost::intrusive::auto_unlink>
    > {
        read_awaitable_base(async_queue& self)noexcept:
            _self( self )
        {}

        read_awaitable_base(read_awaitable_base&&) = delete;

        template<class _T>
        void set_value(_T&& t) {
            _result.emplace(std::forward<_T>(t));
            _h.resume();
        }

        void set_stopped()noexcept {
            _h.resume();
        }

        bool await_ready()noexcept {
            if (_self._closed) [[unlikely]] {
                if (!_self._q.empty()) {
                    _result = std::move(_self._q.front());
                    _self._q.pop_front();
                }
                return true;
            }
            if (_self._q.empty()) {
                _self._readers.push_back(*this);
                return false;
            }
            _result = std::move(_self._q.front());
            _self._q.pop_front();
            return true;  
        }

        template<class Promise>
        void await_suspend(std::coroutine_handle<Promise> h) {
            _h = h;
            return;
        }

        std::optional<T> await_resume() {
            if (is_linked())
                unlink();
            return std::move(_result);
        }
    protected:
        async_queue& _self;
        std::coroutine_handle<> _h{nullptr};
        std::optional<T> _result{};
    };

    struct read_awaitable : read_awaitable_base {
        read_awaitable(async_queue& self)noexcept :
            read_awaitable_base(self)
        {
        }

        ~read_awaitable() {
            destroy_stop_callback();
        }

        template<class Promise>
        std::coroutine_handle<> await_suspend(std::coroutine_handle<Promise> h) {
            if constexpr (requires {
                stdexec::get_env(h.promise());
                stdexec::get_stop_token(stdexec::get_env(h.promise()));
            } && !stdexec::unstoppable_token<stdexec::stop_token_of_t<stdexec::env_of_t<Promise>>>) {
                const auto& env = stdexec::get_env(h.promise());
                const auto& token = stdexec::get_stop_token(env);
                if (token.stop_requested()) [[unlikely]] {
                    return h;
                }
                construct_stop_callback(token, h);
            }
            this->_h = h;
            return std::noop_coroutine();
        }
    private:
        template<class Token, class Promise>
        void construct_stop_callback(Token token, std::coroutine_handle<Promise> h) {
            using stop_callback_t = stdexec::stop_token_of_t<stdexec::env_of_t<Promise>>::template callback_type<std::coroutine_handle<Promise>>;
            if constexpr (sizeof(stop_callback_t) > sizeof(_storage)) {
                //std::cout << "Allocate\n";
                _stop_callback = new stop_callback_t(token, h);
                _stop_callback_destructor = +[](void* cb)noexcept {
                    delete reinterpret_cast<stop_callback_t*>(cb);
                };
            }
            else {
                std::construct_at(reinterpret_cast<stop_callback_t*>(_storage), token, h);
                _stop_callback = _storage;
                _stop_callback_destructor = +[](void* cb)noexcept {
                    std::destroy_at(reinterpret_cast<stop_callback_t*>(cb));
                };
            }
        }

        void destroy_stop_callback()noexcept {
            if (!_stop_callback)
                return;
            _stop_callback_destructor(_stop_callback);
            _stop_callback = nullptr;
        }

        alignas(std::max_align_t) char _storage[64];
        void* _stop_callback = nullptr;
        void (*_stop_callback_destructor)(void*)noexcept = nullptr;
    };

    using readers_list_t = boost::intrusive::list<read_awaitable_base, boost::intrusive::constant_time_size<false>>;

    container_type _q;
    const std::size_t _max;
    readers_list_t _readers;
    bool _closed{ false };
};

} // namespace ice

// #include <exec/task.hpp>
// #include <exec/async_scope.hpp>

// #include <iostream>

// void test() {
//     async_queue<int> q(10);

//     auto reader = [&](std::string name)->exec::task<void> {
//         while (true) {
//             std::optional<int> x = co_await q.async_pop();
//             if (!x) {
//                 std::cout << "Stopped.\n";
//                 co_return;
//             }
//             std::cout << name << ": " << *x << '\n';
//         }
//     };

//     auto writer = [&]()->exec::task<void> {
//         for (int i = 0; i < 20; ++i) {
//             q.push(i);
//         }
//         q.close();
//         std::cout << "Writer closed.\n";
//         co_return;
//     };

//     exec::async_scope scope;

//     scope.spawn(reader("Mike"));
//     scope.spawn(reader("Amy"));
//     scope.spawn(reader("Wuyifan"));
//     scope.spawn(reader("John"));

//     scope.spawn(writer());

//     stdexec::sync_wait(scope.on_empty());
// }

// int main() {
//     test();
// }