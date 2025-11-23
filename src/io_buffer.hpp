#pragma once

#include "config.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/buffer.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <exception>
#include <memory>
#include <stdexcept>

namespace ice {

struct io_buffer_pool;

class io_buffer {
  public:
    io_buffer(std::size_t head_room = default_head_room(),
              std::size_t tail_room = default_tail_room()) {
        if (head_room + tail_room == 0)
            return;
        _data = new uint8_t[head_room + tail_room];
        _capacity = head_room + tail_room;
        _start = head_room;
        _end = head_room;
    }

    io_buffer(const void *data, std::size_t size,
              std::size_t head_room = default_head_room(),
              std::size_t tail_room = default_tail_room())
        : io_buffer(head_room, (data ? size : 0) + tail_room) {
        if (data)
            std::copy(static_cast<const uint8_t *>(data),
                      static_cast<const uint8_t *>(data) + size,
                      _data + _start);
        _end += data ? size : 0;
    }

    io_buffer(const io_buffer &other) {
        if (other._data) {
            _data = new uint8_t[other._capacity];
            _capacity = other._capacity;
            _start = other._start;
            _end = other._end;
            std::copy(other.begin(), other.end(), _data + _start);
        }
    }

    io_buffer &operator=(const io_buffer &other) {
        if (this == &other)
            return *this;
        if (!other._data) {
            reset();
            return *this;
        }
        uint8_t *tmp = new uint8_t[other._capacity];
        reset();
        _data = tmp;
        _capacity = other._capacity;
        _start = other._start;
        _end = other._end;
        std::copy(other.begin(), other.end(), _data + _start);
        return *this;
    }

    io_buffer(io_buffer &&other) noexcept { other.swap(*this); }

    io_buffer &operator=(io_buffer &&other) noexcept {
        if (this == &other)
            return *this;
        reset();
        other.swap(*this);
        return *this;
    }

    ~io_buffer() { delete[] _data; }

    void *data() noexcept { return _data + _start; }

    const void *data() const noexcept { return _data + _start; }

    std::size_t size() const noexcept { return _end - _start; }

    std::size_t capacity() const noexcept { return _capacity; }

    std::size_t head_room() const noexcept { return _start; }

    std::size_t tail_room() const noexcept { return _capacity - _end; }

    io_buffer_pool *pool() noexcept { return _pool; }

    const io_buffer_pool *pool() const noexcept { return _pool; }

    void set_pool(io_buffer_pool *pool) noexcept { _pool = pool; }

    const io_buffer *next() const noexcept { return _next; }

    io_buffer *next() noexcept { return _next; }

    void set_next(io_buffer *next) noexcept { _next = next; }

    void swap(io_buffer &other) noexcept {
        std::swap(_data, other._data);
        std::swap(_capacity, other._capacity);
        std::swap(_start, other._start);
        std::swap(_end, other._end);
    }

    uint8_t *release() noexcept {
        uint8_t *data = _data;
        _data = nullptr;
        _capacity = 0;
        _start = 0;
        _end = 0;
        return data;
    }

    void reset() noexcept { delete[] release(); }

    uint8_t *begin() noexcept { return _data + _start; }

    const uint8_t *begin() const noexcept { return _data + _start; }

    uint8_t *end() noexcept { return _data + _end; }

    const uint8_t *end() const noexcept { return _data + _end; }

    net::mutable_buffer buffer() noexcept {
        return net::mutable_buffer(data(), size());
    }

    net::mutable_buffer prepare_front(std::size_t n) {
        if (n <= head_room())
            return net::mutable_buffer(_data + _start - n, n);
        reserve_head_room(n);
        return prepare_front(n);
    }

    net::mutable_buffer prepare_back(std::size_t n) {
        if (n <= tail_room())
            return net::mutable_buffer(_data + _end, n);
        reserve_tail_room(n);
        return prepare_back(n);
    }

    void commit_front(std::size_t n) noexcept {
        assert(n <= head_room());
        _start -= n;
    }

    void commit_back(std::size_t n) noexcept {
        assert(n <= tail_room());
        _end += n;
    }

    void consume_front(std::size_t n) noexcept {
        assert(n <= size());
        _start += n;
    }

    void consume_back(std::size_t n) noexcept {
        assert(n <= size());
        _end -= n;
    }

    void reshape(std::size_t head_room, std::size_t tail_room) {
        if (head_room + tail_room + size() <= capacity()) {
            std::size_t size_tmp = size();
            if (head_room > _start) {
                std::move_backward(begin(), end(), _data + head_room);
                _start = head_room;
                _end = _start + size_tmp;
                return;
            }
            if (tail_room > _capacity - _end) {
                std::move(begin(), end(), _data + head_room);
                _start = head_room;
                _end = _start + size_tmp;
                return;
            }
            return;
        }
        io_buffer tmp(data(), size(), head_room, tail_room);
        swap(tmp);
    }

    void shrink_to_fit() {
        io_buffer tmp(data(), size(), 0, 0);
        swap(tmp);
    }

    void clear() noexcept { _start = _end = 0; }

    static constexpr std::size_t default_head_room() noexcept { return 64; }

    static constexpr std::size_t default_tail_room() noexcept { return 1024; }

  private:
    void reserve_head_room(std::size_t n) {
        if (n <= head_room())
            return;
        std::size_t new_head_room = std::max((head_room() + size()) * 2, n);
        reshape(new_head_room, tail_room());
    }

    void reserve_tail_room(std::size_t n) {
        if (n <= tail_room())
            return;
        std::size_t new_tail_room = std::max((size() + tail_room()) * 2, n);
        reshape(head_room(), new_tail_room);
    }

    uint8_t *_data{nullptr};
    std::size_t _capacity{0};
    std::size_t _start{0};
    std::size_t _end{0};

    io_buffer_pool *_pool{nullptr};
    io_buffer *_next{nullptr};
};

struct io_buffer_pool {
    io_buffer_pool(
        std::size_t max_size = std::numeric_limits<std::size_t>::max()) noexcept
        : _max_size(max_size) {}

    io_buffer_pool(const io_buffer_pool &) = delete;
    io_buffer_pool(io_buffer_pool &&) = delete;
    io_buffer_pool &operator=(const io_buffer_pool &) = delete;
    io_buffer_pool &operator=(io_buffer_pool &&) = delete;

    ~io_buffer_pool() { clear(); }

    void clear() noexcept {
        while (_buffers) {
            auto b = _buffers;
            _buffers = _buffers->next();
            delete b;
        }
    }

    std::size_t size() const noexcept { return _size; }

    std::size_t max_size() const noexcept { return _max_size; }

    std::unique_ptr<io_buffer>
    get(std::size_t head_room = io_buffer::default_head_room(),
        std::size_t tail_room = io_buffer::default_tail_room()) {
        if (!_buffers) [[unlikely]] {
            auto b = std::make_unique<io_buffer>(head_room, tail_room);
            b->set_pool(this);
            return b;
        }
        auto *tmp = _buffers;
        _buffers = tmp->next();
        tmp->reshape(head_room, tail_room);
        tmp->set_pool(this);
        --_size;
        return std::unique_ptr<io_buffer>(tmp);
    }

    void put(std::unique_ptr<io_buffer> buffer) noexcept {
        if (_size >= _max_size || !buffer) [[unlikely]]
            return;
        buffer->clear();
        buffer->set_next(_buffers);
        _buffers = buffer.release();
        ++_size;
    }

  private:
    std::size_t _max_size;
    io_buffer *_buffers{nullptr};
    std::size_t _size{0};
};

struct io_buffer_ptr {
    io_buffer_ptr() noexcept {}
    io_buffer_ptr(io_buffer_pool *pool,
                  std::size_t head_room = io_buffer::default_head_room(),
                  std::size_t tail_room = io_buffer::default_tail_room())
        : _buffer(pool ? pool->get(head_room, tail_room).release()
                       : std::make_unique<io_buffer>(head_room, tail_room)
                             .release()) {}

    io_buffer_ptr(std::unique_ptr<io_buffer> buffer) noexcept
        : _buffer(buffer.release()) {}

    io_buffer_ptr(const io_buffer_ptr &) = delete;
    io_buffer_ptr &operator=(const io_buffer_ptr &) = delete;

    io_buffer_ptr(io_buffer_ptr &&other) noexcept
        : _buffer(std::exchange(other._buffer, nullptr)) {}

    io_buffer_ptr &operator=(io_buffer_ptr &&other) noexcept {
        if (this != &other) {
            reset();
            swap(other);
        }
        return *this;
    }

    ~io_buffer_ptr() noexcept { reset(); }

    void reset() noexcept {
        if (!_buffer)
            return;
        if (_buffer->pool()) {
            auto &pool = *_buffer->pool();
            pool.put(
                std::unique_ptr<io_buffer>(std::exchange(_buffer, nullptr)));
            return;
        }
        delete _buffer;
        _buffer = nullptr;
    }

    std::unique_ptr<io_buffer> release() noexcept {
        std::unique_ptr<io_buffer> buffer(_buffer);
        _buffer = nullptr;
        return buffer;
    }

    void swap(io_buffer_ptr &other) noexcept {
        std::swap(_buffer, other._buffer);
    }

    operator bool() const noexcept { return _buffer != nullptr; }

    const io_buffer *operator->() const noexcept { return _buffer; }

    io_buffer *operator->() noexcept { return _buffer; }

    const io_buffer &operator*() const noexcept { return *_buffer; }

    io_buffer &operator*() noexcept { return *_buffer; }

    bool empty() const noexcept { return _buffer == nullptr; }

    friend bool operator==(const io_buffer_ptr &lhs,
                           const std::nullptr_t &rhs) noexcept {
        return lhs._buffer == rhs;
    }

    friend bool operator==(const std::nullptr_t &lhs,
                           const io_buffer_ptr &rhs) noexcept {
        return rhs._buffer == lhs;
    }

  private:
    io_buffer *_buffer{nullptr};
};

} // namespace ice