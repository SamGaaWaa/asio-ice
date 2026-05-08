#pragma once

#include <exception>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <variant>

#include "boost/intrusive/list.hpp"
#include "boost/intrusive/list_hook.hpp"

#include <stdexec/execution.hpp>

namespace exsctp {

namespace __shared_promise_detail {

template <class... Args>
struct operation_base
    : public boost::intrusive::list_base_hook<
          boost::intrusive::link_mode<boost::intrusive::auto_unlink>> {
    static_assert((true && ... && std::is_copy_constructible_v<Args>));
    operation_base() = default;
    operation_base(const operation_base &) = delete;
    operation_base &operator=(const operation_base &) = delete;
    operation_base(operation_base &&) = delete;
    operation_base &operator=(operation_base &&) = delete;

    virtual void set_value(const Args &...) noexcept = 0;
    virtual void set_error(const std::exception_ptr &) noexcept = 0;
    virtual void set_stopped() noexcept = 0;
};

template <>
struct operation_base<void>
    : public boost::intrusive::list_base_hook<
          boost::intrusive::link_mode<boost::intrusive::auto_unlink>> {
    operation_base() = default;
    operation_base(const operation_base &) = delete;
    operation_base &operator=(const operation_base &) = delete;
    operation_base(operation_base &&) = delete;
    operation_base &operator=(operation_base &&) = delete;

    virtual void set_value() noexcept = 0;
    virtual void set_error(const std::exception_ptr &) noexcept = 0;
    virtual void set_stopped() noexcept = 0;
};

template <class... Args> struct shared_promise {
    static_assert((true && ... && std::is_copy_constructible_v<Args>));
    using operation_list_type =
        boost::intrusive::list<operation_base<Args...>,
                               boost::intrusive::constant_time_size<false>>;

    shared_promise() = default;
    shared_promise(const shared_promise &) = delete;
    shared_promise &operator=(const shared_promise &) = delete;
    shared_promise(shared_promise &&) = delete;
    shared_promise &operator=(shared_promise &&) = delete;

    void set_value(const Args &...args) noexcept {
        operation_list_type tmp;
        tmp.swap(_operations);
        while (!tmp.empty()) {
            auto &op = tmp.front();
            tmp.pop_front();
            op.set_value(args...);
        }
    }

    void set_one_value(const Args &...args) noexcept {
        if (_operations.empty())
            return;
        auto &op = _operations.front();
        _operations.pop_front();
        op.set_value(args...);
    }

    void set_error(const std::exception_ptr &error) noexcept {
        operation_list_type tmp;
        tmp.swap(_operations);
        while (!tmp.empty()) {
            auto &op = tmp.front();
            tmp.pop_front();
            op.set_error(error);
        }
    }

    void set_one_error(const std::exception_ptr &error) noexcept {
        if (_operations.empty())
            return;
        auto &op = _operations.front();
        _operations.pop_front();
        op.set_error(error);
    }

    void set_stopped() noexcept {
        operation_list_type tmp;
        tmp.swap(_operations);
        while (!tmp.empty()) {
            auto &op = tmp.front();
            tmp.pop_front();
            op.set_stopped();
        }
    }

    void set_one_stopped() noexcept {
        if (_operations.empty())
            return;
        auto &op = _operations.front();
        _operations.pop_front();
        op.set_stopped();
    }

    bool empty() const noexcept { return _operations.empty(); }

  private:
    struct future {
        using sender_concept = stdexec::sender_t;
        using completion_signatures = stdexec::completion_signatures<
            stdexec::set_value_t(Args...),
            stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>;

        future(const future &) = default;
        future &operator=(const future &) = default;
        future(future &&) = default;
        future &operator=(future &&) = default;

      private:
        friend struct shared_promise;

        future(operation_list_type &ops) : _ops{&ops} {}

        template <stdexec::receiver R>
        struct op_t final : public operation_base<Args...> {
            template <stdexec::receiver _R>
            op_t(_R &&r, operation_list_type &ops)
                : _r{std::forward<_R>(r)}, _ops{ops} {}

            void set_value(const Args &...args) noexcept override {
                if constexpr ((true && ... &&
                               std::is_nothrow_copy_constructible_v<Args>)) {
                    stdexec::set_value(std::move(_r), args...);
                } else {
                    try {
                        stdexec::set_value(std::move(_r), args...);
                    } catch (...) {
                        set_error(std::current_exception());
                    }
                }
            }

            void set_error(const std::exception_ptr &error) noexcept override {
                stdexec::set_error(std::move(_r), error);
            }

            void set_stopped() noexcept override {
                stdexec::set_stopped(std::move(_r));
            }

            void start() & noexcept { _ops.push_back(*this); }

          private:
            R _r;
            operation_list_type &_ops;
        };

        template <stdexec::receiver R>
        struct cancelable_op_t final : public operation_base<Args...> {
            template <stdexec::receiver _R>
            cancelable_op_t(_R &&r, operation_list_type &ops)
                : _r{std::forward<_R>(r)}, _ops{ops} {}

            void set_value(const Args &...args) noexcept override {
                _stop_cb.reset();
                if constexpr ((true && ... &&
                               std::is_nothrow_copy_constructible_v<Args>)) {
                    stdexec::set_value(std::move(_r), args...);
                } else {
                    try {
                        stdexec::set_value(std::move(_r), args...);
                    } catch (...) {
                        set_error(std::current_exception());
                    }
                }
            }

            void set_error(const std::exception_ptr &error) noexcept override {
                _stop_cb.reset();
                stdexec::set_error(std::move(_r), error);
            }

            void set_stopped() noexcept override {
                _stop_cb.reset();
                stdexec::set_stopped(std::move(_r));
            }

            void start() & noexcept {
                const auto &env = stdexec::get_env(_r);
                const auto &token = stdexec::get_stop_token(env);
                if (token.stop_requested()) {
                    stdexec::set_stopped(std::move(_r));
                    return;
                }
                _ops.push_back(*this);
                _stop_cb.emplace(token, on_stop_t{*this});
            }

          private:
            struct on_stop_t {
                cancelable_op_t &self;
                void operator()() noexcept {
                    if (self.is_linked())
                        self.unlink();
                    stdexec::set_stopped(std::move(self._r));
                }
            };
            using stop_callback_t = typename stdexec::stop_token_of_t<
                stdexec::env_of_t<R> &>::template callback_type<on_stop_t>;

            R _r;
            operation_list_type &_ops;
            std::optional<stop_callback_t> _stop_cb{};
        };

      public:
        template <stdexec::receiver R>
        stdexec::operation_state auto connect(R &&r) && noexcept {
            if constexpr (stdexec::unstoppable_token<
                              stdexec::stop_token_of_t<stdexec::env_of_t<R>>>) {
                return op_t<std::decay_t<R>>{std::forward<R>(r), *_ops};
            } else {
                return cancelable_op_t<std::decay_t<R>>{std::forward<R>(r),
                                                        *_ops};
            }
        }

      private:
        operation_list_type *_ops;
    };

  public:
    future get_future() noexcept { return {this->_operations}; }

  private:
    operation_list_type _operations;
};

template <> struct shared_promise<void> {
    using operation_list_type =
        boost::intrusive::list<operation_base<void>,
                               boost::intrusive::constant_time_size<false>>;

    shared_promise() = default;
    shared_promise(const shared_promise &) = delete;
    shared_promise &operator=(const shared_promise &) = delete;
    shared_promise(shared_promise &&) = delete;
    shared_promise &operator=(shared_promise &&) = delete;

    void set_value() noexcept {
        operation_list_type tmp;
        tmp.swap(_operations);
        while (!tmp.empty()) {
            auto &op = tmp.front();
            tmp.pop_front();
            op.set_value();
        }
    }

    void set_one_value() noexcept {
        if (_operations.empty())
            return;
        auto &op = _operations.front();
        _operations.pop_front();
        op.set_value();
    }

    void set_error(const std::exception_ptr &error) noexcept {
        operation_list_type tmp;
        tmp.swap(_operations);
        while (!tmp.empty()) {
            auto &op = tmp.front();
            tmp.pop_front();
            op.set_error(error);
        }
    }

    void set_one_error(const std::exception_ptr &error) noexcept {
        if (_operations.empty())
            return;
        auto &op = _operations.front();
        _operations.pop_front();
        op.set_error(error);
    }

    void set_stopped() noexcept {
        operation_list_type tmp;
        tmp.swap(_operations);
        while (!tmp.empty()) {
            auto &op = tmp.front();
            tmp.pop_front();
            op.set_stopped();
        }
    }

    void set_one_stopped() noexcept {
        if (_operations.empty())
            return;
        auto &op = _operations.front();
        _operations.pop_front();
        op.set_stopped();
    }

    bool empty() const noexcept { return _operations.empty(); }

  private:
    struct future {
        using sender_concept = stdexec::sender_t;
        using completion_signatures = stdexec::completion_signatures<
            stdexec::set_value_t(), stdexec::set_error_t(std::exception_ptr),
            stdexec::set_stopped_t()>;

        future(const future &) = default;
        future &operator=(const future &) = default;
        future(future &&) = default;
        future &operator=(future &&) = default;

      private:
        friend struct shared_promise;

        future(operation_list_type &ops) : _ops{&ops} {}

        template <stdexec::receiver R>
        struct op_t final : public operation_base<void> {
            template <stdexec::receiver _R>
            op_t(_R &&r, operation_list_type &ops)
                : _r{std::forward<_R>(r)}, _ops{ops} {}

            void set_value() noexcept override {
                stdexec::set_value(std::move(_r));
            }

            void set_error(const std::exception_ptr &error) noexcept override {
                stdexec::set_error(std::move(_r), error);
            }

            void set_stopped() noexcept override {
                stdexec::set_stopped(std::move(_r));
            }

            void start() & noexcept { _ops.push_back(*this); }

          private:
            R _r;
            operation_list_type &_ops;
        };

        template <stdexec::receiver R>
        struct cancelable_op_t final : public operation_base<void> {
            template <stdexec::receiver _R>
            cancelable_op_t(_R &&r, operation_list_type &ops)
                : _r{std::forward<_R>(r)}, _ops{ops} {}

            void set_value() noexcept override {
                _stop_cb.reset();
                stdexec::set_value(std::move(_r));
            }

            void set_error(const std::exception_ptr &error) noexcept override {
                _stop_cb.reset();
                stdexec::set_error(std::move(_r), error);
            }

            void set_stopped() noexcept override {
                _stop_cb.reset();
                stdexec::set_stopped(std::move(_r));
            }

            void start() & noexcept {
                const auto &env = stdexec::get_env(_r);
                const auto &token = stdexec::get_stop_token(env);
                if (token.stop_requested()) {
                    stdexec::set_stopped(std::move(_r));
                    return;
                }
                _ops.push_back(*this);
                _stop_cb.emplace(token, on_stop_t{*this});
            }

          private:
            struct on_stop_t {
                cancelable_op_t &self;
                void operator()() noexcept {
                    if (self.is_linked())
                        self.unlink();
                    stdexec::set_stopped(std::move(self._r));
                }
            };
            using stop_callback_t = typename stdexec::stop_token_of_t<
                stdexec::env_of_t<R> &>::template callback_type<on_stop_t>;

            R _r;
            operation_list_type &_ops;
            std::optional<stop_callback_t> _stop_cb{};
        };

      public:
        template <stdexec::receiver R>
        stdexec::operation_state auto connect(R &&r) && noexcept {
            if constexpr (stdexec::unstoppable_token<
                              stdexec::stop_token_of_t<stdexec::env_of_t<R>>>) {
                return op_t<std::decay_t<R>>{std::forward<R>(r), *_ops};
            } else {
                return cancelable_op_t<std::decay_t<R>>{std::forward<R>(r),
                                                        *_ops};
            }
        }

      private:
        operation_list_type *_ops;
    };

  public:
    future get_future() noexcept { return {this->_operations}; }

  private:
    operation_list_type _operations;
};

} // namespace __shared_promise_detail

template <class... Args>
using shared_promise = __shared_promise_detail::shared_promise<Args...>;

} // namespace exsctp