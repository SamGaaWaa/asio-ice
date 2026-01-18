#pragma once

#include <stdexec/execution.hpp>

#include <cassert>
#include <optional>
#include <type_traits>

namespace ice::utils {

template <class T> struct inplace_receiver {
    inplace_receiver() {}

    inplace_receiver(const inplace_receiver &) = delete;
    inplace_receiver &operator=(const inplace_receiver &) = delete;
    inplace_receiver(inplace_receiver &&) = delete;
    inplace_receiver &operator=(inplace_receiver &&) = delete;

    template <stdexec::sender S> auto start(S &&s) {
        return stdexec::connect(std::forward<S>(s), receiver{this});
    }

    auto wait() noexcept { return wait_sender{this}; }

    struct op_base {
        op_base() = default;
        op_base(const op_base &) = delete;
        op_base &operator=(const op_base &) = delete;
        op_base(op_base &&) = delete;
        op_base &operator=(op_base &&) = delete;
        void (*set_value)(op_base *, T) noexcept = nullptr;
        void (*set_error)(op_base *, std::exception_ptr) noexcept = nullptr;
        void (*set_stopped)(op_base *) noexcept = nullptr;
    };

    struct env {
        auto query(stdexec::get_stop_token_t) const noexcept {
            return _storage->_source.get_token();
        }
        inplace_receiver *_storage;
    };

    struct receiver {
        using receiver_concept = stdexec::receiver_t;
        template <class T1> void set_value(T1 &&t) && noexcept {
            _storage->set_value(std::forward<T1>(t));
        }
        void set_error(std::exception_ptr e) && noexcept {
            _storage->set_error(std::move(e));
        }
        void set_stopped() && noexcept { _storage->set_stopped(); }
        env get_env() const noexcept { return {_storage}; }
        inplace_receiver *_storage;
    };

    struct wait_sender {
        using sender_concept = stdexec::sender_t;
        using completion_signatures = stdexec::completion_signatures<
            stdexec::set_value_t(T), stdexec::set_error_t(std::exception_ptr),
            stdexec::set_stopped_t()>;
        template <stdexec::receiver R> struct op : op_base {
            template <stdexec::receiver R1>
            op(inplace_receiver *storage, R1 &&r) noexcept
                : _storage(storage), _r(std::forward<R1>(r)) {
                this->set_value = &_set_value;
                this->set_error = &_set_error;
                this->set_stopped = &_set_stopped;
            }
            void start() & noexcept {
                switch (_storage->_var.index()) {
                case 3:
                    return stdexec::set_stopped(std::move(_r));
                case 1:
                    stdexec::set_value(std::move(_r),
                                       std::move(std::get<1>(_storage->_var)));
                    return;
                case 2:
                    stdexec::set_error(std::move(_r),
                                       std::move(std::get<2>(_storage->_var)));
                    return;
                default:
                    break;
                }
                assert(_storage->_waiter == nullptr);
                _storage->_waiter = this;
            }
            static void _set_value(op_base *p, T t) noexcept {
                auto *self = static_cast<op *>(p);
                stdexec::set_value(std::move(self->_r), std::move(t));
            }
            static void _set_error(op_base *p, std::exception_ptr e) noexcept {
                auto *self = static_cast<op *>(p);
                stdexec::set_error(std::move(self->_r), std::move(e));
            }
            static void _set_stopped(op_base *p) noexcept {
                auto *self = static_cast<op *>(p);
                stdexec::set_stopped(std::move(self->_r));
            }

          private:
            inplace_receiver *_storage;
            R _r;
        };

        template <stdexec::receiver R, class Token>
        struct cancellable_op : op_base {
            template <stdexec::receiver R1>
            cancellable_op(inplace_receiver *storage, R1 &&r) noexcept
                : _storage(storage), _r(std::forward<R1>(r)) {
                this->set_value = &_set_value;
                this->set_error = &_set_error;
                this->set_stopped = &_set_stopped;
            }
            struct forward_stop {
                void operator()() noexcept { _storage->_source.request_stop(); }
                inplace_receiver *_storage;
            };
            using stop_callback_t =
                typename Token::template callback_type<forward_stop>;
            void start() & noexcept {
                switch (_storage->_var.index()) {
                case 3:
                    return stdexec::set_stopped(std::move(_r));
                case 1:
                    stdexec::set_value(std::move(_r),
                                       std::move(std::get<1>(_storage->_var)));
                    return;
                case 2:
                    stdexec::set_error(std::move(_r),
                                       std::move(std::get<2>(_storage->_var)));
                    return;
                default:
                    break;
                }
                assert(_storage->_waiter == nullptr);
                _storage->_waiter = this;
                const auto &env = stdexec::get_env(_r);
                const auto &token = stdexec::get_stop_token(env);
                _stop_cb.emplace(token, forward_stop{_storage});
            }
            static void _set_value(op_base *p, T t) noexcept {
                auto *self = static_cast<cancellable_op *>(p);
                self->_stop_cb.reset();
                stdexec::set_value(std::move(self->_r), std::move(t));
            }
            static void _set_error(op_base *p, std::exception_ptr e) noexcept {
                auto *self = static_cast<cancellable_op *>(p);
                self->_stop_cb.reset();
                stdexec::set_error(std::move(self->_r), std::move(e));
            }
            static void _set_stopped(op_base *p) noexcept {
                auto *self = static_cast<cancellable_op *>(p);
                self->_stop_cb.reset();
                stdexec::set_stopped(std::move(self->_r));
            }

          private:
            inplace_receiver *_storage;
            R _r;
            std::optional<stop_callback_t> _stop_cb{};
        };

        template <stdexec::receiver R> auto connect(R &&r) && noexcept {
            using token_t = stdexec::stop_token_of_t<std::decay_t<R>>;
            if constexpr (stdexec::unstoppable_token<token_t>) {
                return op<std::decay_t<R>>(_storage, std::forward<R>(r));
            } else {
                return cancellable_op<std::decay_t<R>, token_t>(
                    _storage, std::forward<R>(r));
            }
        }
        inplace_receiver *_storage;
    };

    template <class T1> void set_value(T1 &&t) noexcept {
        assert(_var.index() == 0);
        if (_waiter) {
            op_base *op = std::exchange(_waiter, nullptr);
            return op->set_value(op, std::forward<T1>(t));
        }
        _var.template emplace<1>(std::forward<T1>(t));
    }

    void set_error(std::exception_ptr e) noexcept {
        assert(_var.index() == 0);
        if (_waiter) {
            op_base *op = std::exchange(_waiter, nullptr);
            return op->set_error(op, std::move(e));
        }
        _var.template emplace<2>(std::move(e));
    }

    void set_stopped() noexcept {
        assert(_var.index() == 0);
        if (_waiter) {
            op_base *op = std::exchange(_waiter, nullptr);
            return op->set_stopped(op);
        }
        _var.template emplace<3>();
    }
    struct stopped_tag{};

    stdexec::inplace_stop_source _source;
    std::variant<std::monostate, T, std::exception_ptr, stopped_tag> _var;
    op_base *_waiter{nullptr};
};

template <> struct inplace_receiver<void> {
    inplace_receiver() {}

    inplace_receiver(const inplace_receiver &) = delete;
    inplace_receiver &operator=(const inplace_receiver &) = delete;
    inplace_receiver(inplace_receiver &&) = delete;
    inplace_receiver &operator=(inplace_receiver &&) = delete;

    template <stdexec::sender S> auto start(S &&s) {
        return stdexec::connect(std::forward<S>(s), receiver{this});
    }

    auto wait() noexcept { return wait_sender{this}; }

    struct op_base {
        op_base() = default;
        op_base(const op_base &) = delete;
        op_base &operator=(const op_base &) = delete;
        op_base(op_base &&) = delete;
        op_base &operator=(op_base &&) = delete;
        void (*set_value)(op_base *) noexcept = nullptr;
        void (*set_error)(op_base *, std::exception_ptr) noexcept = nullptr;
        void (*set_stopped)(op_base *) noexcept = nullptr;
    };

    struct env {
        auto query(stdexec::get_stop_token_t) const noexcept {
            return _storage->_source.get_token();
        }
        inplace_receiver *_storage;
    };

    struct receiver {
        using receiver_concept = stdexec::receiver_t;
        void set_value() && noexcept { _storage->set_value(); }
        void set_error(std::exception_ptr e) && noexcept {
            _storage->set_error(std::move(e));
        }
        void set_stopped() && noexcept { _storage->set_stopped(); }
        env get_env() const noexcept { return {_storage}; }
        inplace_receiver *_storage;
    };

    struct wait_sender {
        using sender_concept = stdexec::sender_t;
        using completion_signatures = stdexec::completion_signatures<
            stdexec::set_value_t(), stdexec::set_error_t(std::exception_ptr),
            stdexec::set_stopped_t()>;
        template <stdexec::receiver R> struct op : op_base {
            template <stdexec::receiver R1>
            op(inplace_receiver *storage, R1 &&r) noexcept
                : _storage(storage), _r(std::forward<R1>(r)) {
                this->set_value = &_set_value;
                this->set_error = &_set_error;
                this->set_stopped = &_set_stopped;
            }
            void start() & noexcept {
                switch (_storage->_state) {
                case STOPPED:
                    _storage->_state = EMPTY;
                    return stdexec::set_stopped(std::move(_r));
                case VALUE:
                    _storage->_state = EMPTY;
                    return stdexec::set_value(std::move(_r));
                case ERROR:
                    _storage->_state = EMPTY;
                    stdexec::set_error(std::move(_r),
                                       std::move(_storage->_error));
                    return;
                default:
                    break;
                }
                assert(_storage->_waiter == nullptr);
                _storage->_waiter = this;
            }
            static void _set_value(op_base *p) noexcept {
                auto *self = static_cast<op *>(p);
                stdexec::set_value(std::move(self->_r));
            }
            static void _set_error(op_base *p, std::exception_ptr e) noexcept {
                auto *self = static_cast<op *>(p);
                stdexec::set_error(std::move(self->_r), std::move(e));
            }
            static void _set_stopped(op_base *p) noexcept {
                auto *self = static_cast<op *>(p);
                stdexec::set_stopped(std::move(self->_r));
            }

          private:
            inplace_receiver *_storage;
            R _r;
        };

        template <stdexec::receiver R, class Token>
        struct cancellable_op : op_base {
            template <stdexec::receiver R1>
            cancellable_op(inplace_receiver *storage, R1 &&r) noexcept
                : _storage(storage), _r(std::forward<R1>(r)) {
                this->set_value = &_set_value;
                this->set_error = &_set_error;
                this->set_stopped = &_set_stopped;
            }
            struct forward_stop {
                void operator()() noexcept { _storage->_source.request_stop(); }
                inplace_receiver *_storage;
            };
            using stop_callback_t =
                typename Token::template callback_type<forward_stop>;
            void start() & noexcept {
                switch (_storage->_state) {
                case STOPPED:
                    _storage->_state = EMPTY;
                    return stdexec::set_stopped(std::move(_r));
                case VALUE:
                    _storage->_state = EMPTY;
                    return stdexec::set_value(std::move(_r));
                case ERROR:
                    _storage->_state = EMPTY;
                    stdexec::set_error(std::move(_r),
                                       std::move(_storage->_error));
                    return;
                }
                assert(_storage->_waiter == nullptr);
                _storage->_waiter = this;
                const auto &env = stdexec::get_env(_r);
                const auto &token = stdexec::get_stop_token(env);
                _stop_cb.emplace(token, forward_stop{_storage});
            }
            static void _set_value(op_base *p) noexcept {
                auto *self = static_cast<cancellable_op *>(p);
                self->_stop_cb.reset();
                stdexec::set_value(std::move(self->_r));
            }
            static void _set_error(op_base *p, std::exception_ptr e) noexcept {
                auto *self = static_cast<cancellable_op *>(p);
                self->_stop_cb.reset();
                stdexec::set_error(std::move(self->_r), std::move(e));
            }
            static void _set_stopped(op_base *p) noexcept {
                auto *self = static_cast<cancellable_op *>(p);
                self->_stop_cb.reset();
                stdexec::set_stopped(std::move(self->_r));
            }

          private:
            inplace_receiver *_storage;
            R _r;
            std::optional<stop_callback_t> _stop_cb{};
        };

        template <stdexec::receiver R> auto connect(R &&r) && noexcept {
            using token_t = stdexec::stop_token_of_t<std::decay_t<R>>;
            if constexpr (stdexec::unstoppable_token<token_t>) {
                return op<std::decay_t<R>>(_storage, std::forward<R>(r));
            } else {
                return cancellable_op<std::decay_t<R>, token_t>(
                    _storage, std::forward<R>(r));
            }
        }
        inplace_receiver *_storage;
    };

    void set_value() noexcept {
        assert(_state == EMPTY);
        if (_waiter) {
            op_base *op = std::exchange(_waiter, nullptr);
            return op->set_value(op);
        }
        _state = VALUE;
    }

    void set_error(std::exception_ptr e) noexcept {
        assert(_state == EMPTY);
        if (_waiter) {
            op_base *op = std::exchange(_waiter, nullptr);
            return op->set_error(op, std::move(e));
        }
        _state = ERROR;
        _error = std::move(e);
    }

    void set_stopped() noexcept {
        assert(_state == EMPTY);
        if (_waiter) {
            op_base *op = std::exchange(_waiter, nullptr);
            return op->set_stopped(op);
        }
        _state = STOPPED;
    }

    enum state_t { EMPTY, STOPPED, VALUE, ERROR };

    stdexec::inplace_stop_source _source;
    state_t _state{EMPTY};
    std::exception_ptr _error{};
    op_base *_waiter{nullptr};
};

} // namespace ice::utils