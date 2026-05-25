#pragma once

#include "config.hpp"

#include <cstddef>
#include <cassert>
#include <memory>
#include <memory_resource>
#include <iostream>

#include <boost/container/small_vector.hpp>

#include <stdexec/execution.hpp>

namespace asioice::utils {

template <size_t Size = 64ull, size_t Alignment = alignof(std::max_align_t)>
class small_buffer_resource final : public std::pmr::memory_resource {
  public:
    explicit small_buffer_resource(
        std::pmr::memory_resource *upstream =
            std::pmr::get_default_resource()) noexcept
        : _upstream{upstream} {}

    small_buffer_resource(const small_buffer_resource &other) = delete;
    small_buffer_resource &operator=(const small_buffer_resource &) = delete;
    small_buffer_resource(small_buffer_resource &&) = delete;
    small_buffer_resource &operator=(small_buffer_resource &&) = delete;

    static auto
    make_small_buffer_resource(std::span<std::byte> storage,
                               std::pmr::memory_resource *upstream =
                                   std::pmr::get_default_resource()) {
        if (storage.size() < sizeof(small_buffer_resource) ||
            reinterpret_cast<std::uintptr_t>(storage.data()) %
                    alignof(small_buffer_resource) !=
                0)
            throw std::invalid_argument(
                "storage is too small or misaligned for small_buffer_resource");
        struct deleter {
            void operator()(small_buffer_resource *ptr) const noexcept {
                ptr->~small_buffer_resource();
            }
        };
        return std::unique_ptr<small_buffer_resource, deleter>(
            new (storage.data()) small_buffer_resource(upstream));
    }

  private:
    void *do_allocate(size_t bytes, size_t alignment) override {
        size_t offset = get_next_block_offset(alignment);
        if (offset + bytes > Size) {
            ICE_IN_DEBUG {
                std::cout
                    << "Allocated with upstream resource, requested size: "
                    << bytes << ", alignment: " << alignment << "\n";
            }
            return _upstream->allocate(bytes, alignment);
        }
        _allocated_blocks.push_back(block{offset, bytes});
        ICE_IN_DEBUG {
            std::cout << "Allocated in small buffer, requested size: " << bytes
                      << ", alignment: " << alignment << "\n";
        }
        return &_storage[offset];
    }

    void do_deallocate(void *ptr, size_t bytes,
                       size_t alignment) noexcept override {
        if (in_buffer(ptr)) {
            assert(!_allocated_blocks.empty());
            if (&_storage[0] + _allocated_blocks.back().offset ==
                (unsigned char *)ptr)
                _allocated_blocks.pop_back();
            return;
        }
        _upstream->deallocate(ptr, bytes, alignment);
    }

    bool do_is_equal(
        const std::pmr::memory_resource &other) const noexcept override {
        return this == std::addressof(other);
    }

  private:
    struct block {
        std::size_t offset;
        std::size_t size;
    };

    bool in_buffer(void *ptr) const noexcept {
        auto p = reinterpret_cast<std::uintptr_t>(ptr);
        auto start = reinterpret_cast<std::uintptr_t>(&_storage[0]);
        auto end = reinterpret_cast<std::uintptr_t>(&_storage[Size]);
        return p >= start && p < end;
    }

    std::size_t get_next_block_offset(std::size_t alignment) const noexcept {
        std::size_t offset = 0;
        if (!_allocated_blocks.empty())
            offset =
                _allocated_blocks.back().offset + _allocated_blocks.back().size;
        std::size_t aligned_offset =
            (offset + alignment - 1) / alignment * alignment;
        return aligned_offset;
    }

    std::pmr::memory_resource *_upstream;
    alignas(Alignment) unsigned char _storage[Size];
    boost::container::small_vector<block, 8> _allocated_blocks{};
};

} // namespace asioice::utils