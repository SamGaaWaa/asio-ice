#include "fixed_buffer.hpp"
#include "scope_guard.hpp"

#include <algorithm>
#include <cassert>

namespace ice {

fixed_buffer::fixed_buffer(fixed_buffer_pool &pool) {
    if (pool.idx().empty()) [[unlikely]] {
        utils::scope_guard guard([this]() noexcept { _state = state::empty; });
        _state = state::allocated;
        _buffer.mem_buffer.data = new char[pool.buffer_size()];
        _buffer.mem_buffer.size = pool.buffer_size();
        guard.dismiss();
        return;
    }
    _state = state::registered;
    _buffer.pool_buffer.pool = &pool;
    _buffer.pool_buffer.idx = pool.idx().front();
    pool.idx().pop_front();
}

fixed_buffer::fixed_buffer(fixed_buffer &&other) noexcept
    : _state{std::exchange(other._state, state::empty)},
      _buffer{other._buffer} {}

fixed_buffer &fixed_buffer::operator=(fixed_buffer &&other) noexcept {
    if (this != &other) {
        reset();
        _state = std::exchange(other._state, state::empty);
        _buffer = other._buffer;
    }
    return *this;
}

net::mutable_registered_buffer fixed_buffer::mutable_registered_buffer() {
    assert(_state == state::registered);
    return _buffer.pool_buffer.pool->registration()[_buffer.pool_buffer.idx];
}

net::const_registered_buffer fixed_buffer::const_registered_buffer() const {
    assert(_state == state::registered);
    return _buffer.pool_buffer.pool->registration()[_buffer.pool_buffer.idx];
}

net::mutable_buffer fixed_buffer::mutable_buffer() noexcept {
    assert(_state != state::empty);
    if (_state == state::registered) [[likely]]
        return this->mutable_registered_buffer().buffer();
    return net::mutable_buffer(_buffer.mem_buffer.data,
                               _buffer.mem_buffer.size);
}

net::const_buffer fixed_buffer::const_buffer() const noexcept {
    assert(_state != state::empty);
    if (_state == state::registered) [[likely]]
        return this->const_registered_buffer().buffer();
    return net::const_buffer(_buffer.mem_buffer.data, _buffer.mem_buffer.size);
}

const void *fixed_buffer::data() const noexcept {
    if (_state == state::empty) [[unlikely]]
        return nullptr;
    return this->const_buffer().data();
}

void *fixed_buffer::data() noexcept {
    if (_state == state::empty) [[unlikely]]
        return nullptr;
    return this->mutable_buffer().data();
}

std::size_t fixed_buffer::size() const noexcept {
    if (_state == state::empty) [[unlikely]]
        return 0;
    return this->const_buffer().size();
}

void fixed_buffer::reset() noexcept {
    switch (_state) {
    case state::empty:
        return;
    case state::allocated:
        delete[] static_cast<char *>(_buffer.mem_buffer.data);
        _state = state::empty;
        return;
    case state::registered:
        _buffer.pool_buffer.pool->idx().push_back(_buffer.pool_buffer.idx);
        _state = state::empty;
        return;
    }
    std::unreachable();
}

fixed_buffer fixed_buffer_pool::get() { return fixed_buffer(*this); }

std::vector<net::mutable_buffer> fixed_buffer_pool::to_buffer_sequence(
    std::vector<std::vector<std::byte>> &buffers) {
    std::vector<net::mutable_buffer> res(buffers.size());
    std::transform(buffers.begin(), buffers.end(), res.begin(),
                   [](auto &b) noexcept {
                       return net::mutable_buffer(b.data(), b.size());
                   });
    return res;
}

} // namespace ice