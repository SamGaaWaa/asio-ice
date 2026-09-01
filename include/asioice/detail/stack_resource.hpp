#pragma once

#include <cstddef>
#include <cstdint>
#include <cassert>
#include <utility>
#include <memory>
#include <memory_resource>

#include "samlog.hpp"

namespace asioice::utils {

class stack_resource final : public std::pmr::memory_resource {
    static constexpr auto get_block_count(void *begin, void *end) {
        const auto d = (uint8_t *)end - (uint8_t *)begin;
        return d / sizeof(std::max_align_t);
    }

    static constexpr auto get_block_count(std::size_t n) {
        return n == 0 ? 0 : ((n - 1) / sizeof(std::max_align_t) + 1);
    }

    static constexpr std::max_align_t *get_aligned(void *buf,
                                                   std::size_t buf_size) {
        return static_cast<std::max_align_t *>(
            std::align(alignof(std::max_align_t), sizeof(std::max_align_t), buf,
                       buf_size));
    }

  public:
    stack_resource(void *buf, std::size_t buf_size,
                   std::pmr::memory_resource *upstream =
                       std::pmr::get_default_resource()) noexcept
        : _buffer{get_aligned(buf, buf_size)},
          _capacity{_buffer == nullptr
                        ? 0
                        : get_block_count(_buffer, (uint8_t *)buf + buf_size)},
          _upstream{upstream}, _top{_buffer} {}

    stack_resource(const stack_resource &other) = delete;
    stack_resource &operator=(const stack_resource &) = delete;
    stack_resource(stack_resource &&) = delete;
    stack_resource &operator=(stack_resource &&) = delete;

  private:
    std::max_align_t *buffer_end() const noexcept {
        return _buffer + _capacity;
    }

    void *allocate_with_upstream(size_t bytes, size_t alignment) {
        if (!_upstream)
            throw std::bad_alloc{};
        SAMLOG_WARN(auto sink) {
            sink("allocated in heap: {} bytes, {} aligned\n", bytes, alignment);
        };
        return _upstream->allocate(bytes, alignment);
    }

    void *do_allocate(size_t bytes, size_t alignment) override {
        if (!_buffer || alignment > alignof(std::max_align_t))
            return allocate_with_upstream(bytes, alignment);
        auto bc = get_block_count(bytes);
        if (bc > buffer_end() - _top)
            return allocate_with_upstream(bytes, alignment);
        const auto new_top = _top + bc;
        auto ptr = _top;
        _top = new_top;
        ++_frame_count;
        return ptr;
    }

    void do_deallocate(void *ptr, size_t bytes,
                       size_t alignment) noexcept override {
        if (!_buffer || alignment > alignof(std::max_align_t))
            return _upstream->deallocate(ptr, bytes, alignment);
        std::max_align_t *ap = static_cast<std::max_align_t *>(ptr);
        if (ap < _buffer || ap > _top || (ap == _top && bytes != 0))
            return _upstream->deallocate(ptr, bytes, alignment);
        assert(_frame_count > 0);
        --_frame_count;
        if (_frame_count == 0) {
            _top = _buffer;
            return;
        }
        const auto bc = get_block_count(bytes);
        if (ap + bc == _top) {
            _top = ap;
        }
    }

    bool do_is_equal(
        const std::pmr::memory_resource &other) const noexcept override {
        return this == std::addressof(other);
    }

    std::max_align_t *const _buffer;
    const std::size_t _capacity;
    std::pmr::memory_resource *const _upstream;

    std::size_t _frame_count{0};
    std::max_align_t *_top;
};

} // namespace asioice::utils