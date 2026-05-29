#include "asioice/detail/io_buffer.hpp"
#include <atomic>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace asioice {

shared_block *shared_block::allocate(std::size_t capacity) {
    void *mem =
        ::operator new(sizeof(shared_block) + capacity * sizeof(std::uint8_t));
    auto *block = new (mem) shared_block;
    block->capacity = capacity;
    block->next = nullptr;
    block->pool = nullptr;
    return block;
}

void shared_block::destroy(shared_block *block) noexcept {
    block->~shared_block();
    ::operator delete(block);
}

void shared_block::add_ref() noexcept {
    refcount.fetch_add(1, std::memory_order_relaxed);
}

bool shared_block::release() noexcept {
    // 获取旧值并减1
    std::size_t old = refcount.fetch_sub(1, std::memory_order_acq_rel);
    if (old == 1) {
        // 引用计数变为0
        if (pool) {
            // 有池，放入池中而不是销毁
            pool->put_block(this);
            return false; // 未销毁
        } else {
            // 无池，直接销毁
            destroy(this);
            return true; // 已销毁
        }
    }
    return false; // 引用计数未变为0
}

std::size_t shared_block::get_refcount() const noexcept {
    return refcount.load(std::memory_order_relaxed);
}

shared_block *io_buffer_pool::get_block(std::size_t capacity) {
    // 1. 尝试从空闲块链表中查找足够容量的块
    shared_block **prev = &_blocks;
    shared_block *curr = _blocks;
    while (curr) {
        if (curr->capacity >= capacity) {
            // 找到合适块，从链表中移除
            *prev = curr->next;
            curr->next = nullptr;
            --_block_count;
            // 确保引用计数为1（从池中取出）
            curr->refcount.store(1, std::memory_order_relaxed);
            // 池指针已设置（之前在 put_block 中设置）
            return curr;
        }
        prev = &curr->next;
        curr = curr->next;
    }
    // 2. 没有合适块，分配新块
    shared_block *block = shared_block::allocate(capacity);
    block->pool = this;
    return block;
}

void io_buffer_pool::put_block(shared_block *block) noexcept {
    if (!block)
        return;
    // 重置引用计数为1（放入池中）
    block->refcount.store(1, std::memory_order_relaxed);
    // 插入到链表头部
    block->next = _blocks;
    _blocks = block;
    ++_block_count;
}

io_buffer::io_buffer()
    : _type(buffer_type::raw), _raw{}, _offset(0), _size(0), _next(nullptr),
      _prev(nullptr), _info(nullptr) {}

io_buffer io_buffer::make_raw(void *data, std::size_t capacity,
                              std::size_t offset, std::size_t size) noexcept {
    io_buffer buf;
    buf._type = buffer_type::raw;
    buf._raw = std::span<std::uint8_t>(static_cast<std::uint8_t *>(data), capacity);
    buf._offset = offset;
    buf._size = size;
    return buf;
}

io_buffer io_buffer::make_shared(std::size_t capacity) {
    io_buffer buf;
    buf._type = buffer_type::shared;
    buf._shared = shared_block::allocate(capacity);
    buf._offset = 0;
    buf._size = 0;
    return buf;
}

io_buffer io_buffer::make_shared(std::size_t capacity, const void *data,
                                 std::size_t size, std::size_t offset) {
    if (offset + size > capacity) {
        throw std::invalid_argument(
            "io_buffer::make_shared: offset + size exceeds capacity");
    }
    io_buffer buf = make_shared(capacity);
    if (data && size > 0) {
        std::memcpy(buf._shared->data() + offset, data, size);
    }
    buf._offset = offset;
    buf._size = size;
    return buf;
}

io_buffer::io_buffer(const io_buffer &other)
    : _type(other._type), _offset(other._offset), _size(other._size),
      _next(other._next), _prev(other._prev), _info(other._info) {
    if (_type == buffer_type::shared) {
        _shared = other._shared;
        _shared->add_ref();
    } else {
        _raw = other._raw;
    }
}

io_buffer::io_buffer(io_buffer &&other)
    : _type(other._type), _offset(other._offset), _size(other._size),
      _next(other._next), _prev(other._prev), _info(other._info) {
    if (_type == buffer_type::shared) {
        _shared = other._shared;
        other._shared = nullptr;
    } else {
        _raw = other._raw;
        other._raw = std::span<std::uint8_t>();
    }
    other._type = buffer_type::raw;
    other._offset = 0;
    other._size = 0;
    other._next = nullptr;
    other._prev = nullptr;
    other._info = nullptr;
}

io_buffer::~io_buffer() {
    if (_type == buffer_type::shared && _shared) {
        _shared->release();
    }
}

io_buffer &io_buffer::operator=(const io_buffer &other) {
    if (this == &other) {
        return *this;
    }
    io_buffer tmp(other);
    swap(tmp);
    return *this;
}

io_buffer &io_buffer::operator=(io_buffer &&other) {
    if (this == &other) {
        return *this;
    }
    io_buffer tmp(std::move(other));
    swap(tmp);
    return *this;
}

void io_buffer::swap(io_buffer &other) noexcept {
    // 交换所有成员，包括 union 的底层字节表示
    // 使用临时存储交换整个对象
    char temp[sizeof(io_buffer)];
    std::memcpy(static_cast<void *>(temp), static_cast<const void *>(this),
                sizeof(io_buffer));
    std::memcpy(static_cast<void *>(this), static_cast<const void *>(&other),
                sizeof(io_buffer));
    std::memcpy(static_cast<void *>(&other), static_cast<const void *>(temp),
                sizeof(io_buffer));
}

io_buffer io_buffer::clone() const {
    io_buffer buf;
    buf._type = buffer_type::shared;

    shared_block *new_block = shared_block::allocate(capacity());

    buf._shared = new_block;
    buf._offset = _offset;
    buf._size = _size;
    if (_size > 0) {
        std::memcpy(buf._shared->data() + _offset, data(), _size);
    }
    return buf;
}

void io_buffer::clear() noexcept { _size = 0; }

bool io_buffer::empty() const noexcept { return _size == 0; }

std::uint8_t *io_buffer::buffer() noexcept {
    return _type == buffer_type::raw ? _raw.data() : _shared->data();
}

const std::uint8_t *io_buffer::buffer() const noexcept {
    return _type == buffer_type::raw ? _raw.data() : _shared->data();
}

std::size_t io_buffer::capacity() const noexcept {
    return _type == buffer_type::raw ? _raw.size() : _shared->capacity;
}

std::uint8_t *io_buffer::data() noexcept { return buffer() + _offset; }

const std::uint8_t *io_buffer::data() const noexcept { return buffer() + _offset; }

std::size_t io_buffer::size() const noexcept { return _size; }

std::size_t io_buffer::head_room() const noexcept { return _offset; }

std::size_t io_buffer::tail_room() const noexcept {
    return capacity() - _offset - _size;
}

void io_buffer::ensure_shared(std::size_t required_capacity) {
    if (capacity() >= required_capacity) {
        // 容量足够，不需要转为 shared
        return;
    }

    shared_block *new_block = shared_block::allocate(required_capacity);

    // 创建新缓冲区
    io_buffer new_buf;
    new_buf._type = buffer_type::shared;
    new_buf._shared = new_block;
    new_buf._offset = _offset;
    new_buf._size = _size;
    // _pool, _next, _prev, _info 保持默认值，swap 时会交换
    if (_size > 0) {
        std::memcpy(new_buf.data(), data(), _size);
    }
    swap(new_buf);
}

void io_buffer::reshape(std::size_t head_room, std::size_t tail_room) {
    // 计算所需容量
    std::size_t required_capacity = head_room + tail_room + _size;

    // 如果当前容量足够，尝试调整数据位置
    if (capacity() >= required_capacity) {
        // 检查是否可以安全移动数据
        // 只有在缓冲区是 shared 类型且引用计数为 1 时才可以移动
        bool can_move_in_place = false;
        if (_type == buffer_type::shared) {
            if (_shared->get_refcount() == 1) {
                can_move_in_place = true;
            }
        }

        if (can_move_in_place) {
            // 计算需要移动的偏移量
            std::size_t new_offset = head_room;
            if (new_offset != _offset && _size > 0) {
                // 需要移动数据
                std::memmove(buffer() + new_offset, data(), _size);
            }
            _offset = new_offset;
            return;
        }
        // 不能移动数据，但容量足够，可以调整 offset（如果数据位置不变）
        // 如果新的 head_room 小于当前 offset，需要移动数据，但不行
        // 如果新的 head_room 大于当前 offset，尾部空间可能不足
        // 简化：分配新缓冲区
        // 注意：这里没有 return，会继续执行分配新缓冲区的代码
        // 这是故意的，因为不能移动数据时我们需要分配新缓冲区
    }

    // 容量不足或不能移动数据，分配新缓冲区
    io_buffer new_buf = make_shared(required_capacity);
    new_buf._offset = head_room;
    new_buf._size = _size;
    if (_size > 0) {
        std::memcpy(new_buf.data(), data(), _size);
    }
    swap(new_buf);
}

std::span<std::uint8_t> io_buffer::prepare_front(std::size_t n) {
    if (head_room() >= n) {
        return {data() - n, n};
    }

    // 需要更多头部空间
    std::size_t need = n - head_room();
    std::size_t required_capacity = capacity() + need;

    shared_block *new_block = shared_block::allocate(required_capacity);

    io_buffer new_buf;
    new_buf._type = buffer_type::shared;
    new_buf._shared = new_block;
    new_buf._offset = n;
    new_buf._size = _size;
    if (_size > 0) {
        std::memcpy(new_buf.data(), data(), _size);
    }
    swap(new_buf);
    return {data() - n, n};
}

std::span<std::uint8_t> io_buffer::prepare_back(std::size_t n) {
    if (tail_room() >= n) {
        return {end(), n};
    }

    // 需要更多尾部空间
    std::size_t need = n - tail_room();
    std::size_t required_capacity = capacity() + need;

    shared_block *new_block = shared_block::allocate(required_capacity);

    io_buffer new_buf;
    new_buf._type = buffer_type::shared;
    new_buf._shared = new_block;
    new_buf._offset = _offset; // 数据位置不变
    new_buf._size = _size;
    if (_size > 0) {
        std::memcpy(new_buf.data(), data(), _size);
    }
    swap(new_buf);
    // 数据已就位，无需移动（数据保持在原 offset）
    return {end(), n};
}

void io_buffer::commit_front(std::size_t n) {
    if (n > head_room()) {
        throw std::invalid_argument(
            "io_buffer::commit_front: n exceeds head_room");
    }
    _offset -= n;
    _size += n;
}

void io_buffer::consume_front(std::size_t n) {
    if (n > _size) {
        throw std::invalid_argument("io_buffer::consume_front: n exceeds size");
    }
    _offset += n;
    _size -= n;
}

void io_buffer::commit_back(std::size_t n) {
    if (n > tail_room()) {
        throw std::invalid_argument(
            "io_buffer::commit_back: n exceeds tail_room");
    }
    _size += n;
}

void io_buffer::consume_back(std::size_t n) {
    if (n > _size) {
        throw std::invalid_argument("io_buffer::consume_back: n exceeds size");
    }
    _size -= n;
}

std::span<std::uint8_t> io_buffer::front_writable(std::size_t n) noexcept {
    if (n > head_room()) {
        n = head_room();
    }
    return std::span<std::uint8_t>(buffer() + _offset - n, n);
}

std::span<std::uint8_t> io_buffer::back_writable(std::size_t n) noexcept {
    if (n > tail_room()) {
        n = tail_room();
    }
    return std::span<std::uint8_t>(buffer() + _offset + _size, n);
}

std::unique_ptr<io_buffer>
io_buffer_pool::get(std::size_t head_room, std::size_t tail_room) {
    io_buffer *buf = nullptr;

    // 1. 尝试从缓冲区链表获取
    if (_buffers) {
        buf = _buffers;
        _buffers = buf->next();
        --_size;
        // 缓冲区从池中取出，清除链表指针
        buf->set_next(nullptr);
    } else {
        // 2. 创建新缓冲区对象
        buf = new io_buffer();
    }

    // 使用 unique_ptr 管理，确保异常安全
    std::unique_ptr<io_buffer> result(buf);

    // 3. 获取或创建 shared_block
    std::size_t required_capacity = head_room + tail_room;
    if (required_capacity == 0)
        return result;

    shared_block *block = get_block(required_capacity);

    // 4. 设置缓冲区
    buf->_type = io_buffer::buffer_type::shared;
    buf->_shared = block;
    // block 的引用计数已在 get_block 中设为1

    // 5. 调整缓冲区布局
    buf->_offset = head_room;
    buf->_size = 0;

    // 6. 设置池指针
    buf->set_pool(this);

    return result;
}

void io_buffer_pool::put(std::unique_ptr<io_buffer> buffer) noexcept {
    if (_size >= _max_size || !buffer) [[unlikely]]
        return;

    // 释放缓冲区对 shared_block 的引用
    if (buffer->_type == io_buffer::buffer_type::shared &&
        buffer->_shared) {
        // release() 会检查引用计数，如果为0且 block->pool 不为空，则放入
        // _blocks 链表
        buffer->_shared->release();
        buffer->_shared = nullptr;
    }

    buffer->clear();
    buffer->_type = io_buffer::buffer_type::raw; // 重置为 raw 类型
    buffer->_raw = std::span<std::uint8_t>();       // 清空 raw 数据

    buffer->set_next(_buffers);
    _buffers = buffer.release();
    ++_size;
}

} // namespace asioice