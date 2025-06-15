#pragma once

#include <bit>
#include <exception>

#include "config.hpp"

#if ASIOICE_USE_BOOST > 0
#include <boost/asio/buffer_registration.hpp>
namespace ice {
namespace net = boost::asio;
} // namespace ice
#else
#include <asio/buffer_registration.hpp>
namespace ice {
namespace net = asio;
} // namespace ice
#endif

#include <boost/circular_buffer.hpp>

namespace ice {

struct fixed_buffer_pool;

struct fixed_buffer {
    fixed_buffer() = default;

    fixed_buffer(fixed_buffer &&other) noexcept;
    fixed_buffer &operator=(fixed_buffer &&other) noexcept;
    fixed_buffer(const fixed_buffer &) = delete;
    fixed_buffer &operator=(const fixed_buffer &) = delete;

    ~fixed_buffer() { reset(); }

    bool empty() const noexcept { return _state == state::empty; }

    bool registered() const noexcept { return _state == state::registered; }

    bool allocated() const noexcept { return _state == state::allocated; }

    net::mutable_registered_buffer mutable_registered_buffer();
    net::const_registered_buffer const_registered_buffer() const;
    net::mutable_buffer mutable_buffer() noexcept;
    net::const_buffer const_buffer() const noexcept;
    const void *data() const noexcept;
    void *data() noexcept;
    std::size_t size() const noexcept;
    void reset() noexcept;

  private:
    friend struct fixed_buffer_pool;
    fixed_buffer(fixed_buffer_pool &pool);

    struct pool_buffer {
        fixed_buffer_pool *pool{nullptr};
        std::size_t idx{0};
    };

    struct mem_buffer {
        void *data{nullptr};
        std::size_t size{0};
    };

    enum struct state : char { empty, registered, allocated };

    state _state{state::empty};
    union {
        pool_buffer pool_buffer;
        mem_buffer mem_buffer;
    } _buffer{};
};

struct fixed_buffer_pool {
    template <class Executor>
    fixed_buffer_pool(Executor &ex, std::size_t count, std::size_t buffer_size)
        : _buffer_size(std::bit_ceil(buffer_size)),
          _buffers(std::bit_ceil(count), std::vector<std::byte>(_buffer_size)),
          _reg(ex, to_buffer_sequence(_buffers)), _idx(_buffers.size()) {
        for (std::size_t i = 0; i < _buffers.size(); ++i)
            _idx.push_back(i);
    }

    fixed_buffer_pool(fixed_buffer_pool &&) = delete;
    fixed_buffer_pool &operator=(fixed_buffer_pool &&) = delete;
    fixed_buffer_pool(const fixed_buffer_pool &) = delete;
    fixed_buffer_pool &operator=(const fixed_buffer_pool &) = delete;

    ~fixed_buffer_pool() noexcept { assert(_idx.size() == _buffers.size()); }

    std::size_t buffer_size() const noexcept { return _buffer_size; }

    std::size_t buffer_count() const noexcept { return _buffers.size(); }

    fixed_buffer get();

  private:
    friend struct fixed_buffer;
    static std::vector<net::mutable_buffer>
    to_buffer_sequence(std::vector<std::vector<std::byte>> &buffers);
    auto &idx() noexcept { return _idx; }
    const auto &idx() const noexcept { return _idx; }
    auto &registration() noexcept { return _reg; }
    const auto &registration() const noexcept { return _reg; }

    std::size_t _buffer_size;
    std::vector<std::vector<std::byte>> _buffers;
    net::buffer_registration<std::vector<net::mutable_buffer>> _reg;
    boost::circular_buffer<std::size_t> _idx;
};

} // namespace ice