#pragma once

#include "plf_hive.h"

#include <cstddef>
#include <type_traits>
#include <utility>

namespace ice {

namespace __object_pool_detail {

template <class T> struct object_storage {
    template <class... Args>
    object_storage(Args &&...args) noexcept(
        std::is_nothrow_constructible_v<T, Args...>)
        : _val(std::forward<Args>(args)...) {}

    object_storage(const object_storage &) = delete;
    object_storage(object_storage &&) = delete;
    object_storage &operator=(const object_storage &) = delete;
    object_storage &operator=(object_storage &&) = delete;

    T *get() noexcept { return &_val; }

    const T *get() const noexcept { return &_val; }

    void increment_use_count() noexcept { _use_count++; }

    void decrement_use_count() noexcept { _use_count--; }

    std::size_t use_count() const noexcept { return _use_count; }

  private:
    std::size_t _use_count = 0;
    T _val;
};

} // namespace __object_pool_detail

template <class T> struct object_pool;

template <class T> struct object_ptr {
    object_ptr() = default;

    object_ptr(const object_ptr &other) noexcept
        : _pool(other._pool), _ptr(other._ptr) {
        if (_ptr) {
            _ptr->increment_use_count();
        }
    }

    object_ptr &operator=(const object_ptr &other) noexcept {
        if (this != &other) {
            reset();
            _pool = other._pool;
            _ptr = other._ptr;
            if (_ptr) {
                _ptr->increment_use_count();
            }
        }
        return *this;
    }

    object_ptr(object_ptr &&other) noexcept
        : _pool(std::exchange(other._pool, nullptr)),
          _ptr(std::exchange(other._ptr, nullptr)) {}

    object_ptr &operator=(object_ptr &&other) noexcept {
        if (this != &other) {
            reset();
            _pool = std::exchange(other._pool, nullptr);
            _ptr = std::exchange(other._ptr, nullptr);
        }
        return *this;
    }

    const T *get() const noexcept { return _ptr->get(); }

    T *get() noexcept { return _ptr->get(); }

    T *operator->() noexcept { return _ptr->get(); }

    const T *operator->() const noexcept { return _ptr->get(); }

    operator bool() const noexcept { return _ptr != nullptr; }

    T &operator*() noexcept { return *_ptr->get(); }

    const T &operator*() const noexcept { return *_ptr->get(); }

    std::size_t use_count() const noexcept {
        return _ptr ? _ptr->use_count() : 0;
    }

    ~object_ptr() noexcept { reset(); }

    void reset() noexcept {
        if (!_ptr)
            return;
        _ptr->decrement_use_count();
        if (_ptr->use_count() == 0) {
            _pool->erase(_pool->get_iterator(_ptr));
        }
        _ptr = nullptr;
    }

  private:
    friend struct object_pool<T>;

    object_ptr(plf::hive<__object_pool_detail::object_storage<T>> &pool,
               __object_pool_detail::object_storage<T> *ptr) noexcept
        : _pool(&pool), _ptr(ptr) {
        if (_ptr)
            _ptr->increment_use_count();
    }

    plf::hive<__object_pool_detail::object_storage<T>> *_pool{nullptr};
    __object_pool_detail::object_storage<T> *_ptr{nullptr};
};

template <class T> struct object_pool {
    object_pool() = default;

    object_pool(const object_pool &) = delete;
    object_pool(object_pool &&) noexcept = default;

    object_pool &operator=(const object_pool &) = delete;
    object_pool &operator=(object_pool &&) noexcept = default;

    template <class... Args> object_ptr<T> create(Args &&...args) {
        auto *ptr = &*_pool.emplace(std::forward<Args>(args)...);
        return object_ptr<T>(_pool, ptr);
    }

  private:
    plf::hive<__object_pool_detail::object_storage<T>> _pool;
};

} // namespace ice