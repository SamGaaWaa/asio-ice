#pragma once

#include <atomic>
#include <cstddef>
#include <span>
#include <cstdint>
#include <memory>
#include <limits>
#include <utility>

namespace asioice {

struct io_buffer;
struct io_buffer_pool;
struct io_buffer_ptr;

// 共享内存块，支持引用计数和池回收
struct shared_block {
    std::atomic<std::size_t> refcount{1};
    std::size_t capacity;
    shared_block *next{nullptr};
    io_buffer_pool *pool{nullptr};

    std::uint8_t *data() noexcept {
        return static_cast<std::uint8_t *>(static_cast<void *>(this)) +
               sizeof(shared_block);
    }

    const std::uint8_t *data() const noexcept {
        return static_cast<const std::uint8_t *>(
                   static_cast<const void *>(this)) +
               sizeof(shared_block);
    }

    static shared_block *allocate(std::size_t capacity);
    static void destroy(shared_block *block) noexcept;

    void add_ref() noexcept;
    bool release() noexcept; // 返回 true 表示实际销毁，false 表示放入池中
    std::size_t get_refcount() const noexcept;
};

/*
    io_buffer 异常安全性说明：
    - 默认构造、移动构造、移动赋值、析构：noexcept
    - 拷贝构造：noexcept（引用计数操作为原子操作，不会失败）
    - 拷贝赋值、移动赋值：强异常安全（使用 copy-and-swap 或 move-and-swap）
    - make_shared、reshape、prepare_front、prepare_back：强异常安全
    -
   commit_front、consume_front、commit_back、consume_back：强异常安全（仅参数检查）
    -
   clone、make_shared(带数据)：基本异常安全（内存分配成功但拷贝失败时，已分配内存自动释放）
    - swap：noexcept
    - 所有其他操作：noexcept 或强异常安全
*/
struct io_buffer {
    enum class buffer_type : char { raw, shared };

    /*
        创建不拥有所有权的 io_buffer
        @param data 缓冲区指针
        @param capacity 缓冲区大小
        @param offset data() 相对 buffer() 的偏移
        @param size size()
    */
    static io_buffer make_raw(void *data, std::size_t capacity,
                              std::size_t offset = 0,
                              std::size_t size = 0) noexcept;

    /*
        创建共享所有权的 io_buffer
        @param capacity 缓冲区大小
        @throws std::bad_alloc 内存分配失败
        @note 强异常安全：如果抛出异常，没有副作用
    */
    static io_buffer make_shared(std::size_t capacity);

    /*
        创建共享所有权的 io_buffer，拷贝给定数据
        @param capacity 缓冲区大小
        @param data 数据指针
        @param size 数据长度
        @param offset 数据拷贝到的位置，相对 buffer() 的偏移
        @throws std::invalid_argument offset + size 超出 capacity
        @throws std::bad_alloc 内存分配失败
        @note 基本异常安全：如果内存分配成功但拷贝失败（极不可能），
              已分配的内存会被自动释放，没有内存泄漏
    */
    static io_buffer make_shared(std::size_t capacity, const void *data,
                                 std::size_t size, std::size_t offset = 0);

    io_buffer(const io_buffer &);
    io_buffer(io_buffer &&);
    io_buffer &operator=(const io_buffer &);
    io_buffer &operator=(io_buffer &&);
    ~io_buffer();

    void swap(io_buffer &other) noexcept;

    /*
         深拷贝，返回一个共享所有权的 io_buffer（不管当前 buffer_type() 是什么）
        @throws std::bad_alloc 内存分配失败
        @note 基本异常安全：如果内存分配成功但拷贝失败（极不可能），
              已分配的内存会被自动释放，没有内存泄漏
    */
    io_buffer clone() const;

    void clear() noexcept;

    /*
        当前缓冲区类型
    */
    buffer_type type() const noexcept { return _type; }
    bool empty() const noexcept;

    std::uint8_t *buffer() noexcept;
    const std::uint8_t *buffer() const noexcept;
    std::size_t capacity() const noexcept;

    std::uint8_t *data() noexcept;
    const std::uint8_t *data() const noexcept;
    std::size_t size() const noexcept;
    const std::uint8_t *begin() const noexcept { return data(); }
    std::uint8_t *begin() noexcept { return data(); }
    const std::uint8_t *end() const noexcept { return data() + size(); }
    std::uint8_t *end() noexcept { return data() + size(); }

    void *info() const noexcept { return _info; }

    void set_info(void *info) noexcept { _info = info; }

    io_buffer *next() const noexcept { return _next; }

    void set_next(io_buffer *next) noexcept { _next = next; }

    io_buffer *prev() const noexcept { return _prev; }

    void set_prev(io_buffer *prev) noexcept { _prev = prev; }

    bool is_linked() const noexcept { return _next || _prev; }

    io_buffer_pool *pool() const noexcept { return _pool; }
    void set_pool(io_buffer_pool *pool) noexcept { _pool = pool; }

    static constexpr std::size_t default_head_room() noexcept { return 64; }
    static constexpr std::size_t default_tail_room() noexcept { return 1024; }

    std::size_t head_room() const noexcept;

    std::size_t tail_room() const noexcept;

    /*
        调整 head_room 和 tail_room，如果容量不足则分配新缓冲区
        调用后 size() 不变，但数据可能被移动（仅当缓冲区是 shared 且引用计数为 1
       时）
        @throws std::bad_alloc 内存分配失败
        @note 强异常安全：如果抛出异常，对象状态不变
    */
    void reshape(std::size_t head_room, std::size_t tail_room);

    /*
        使 head_room() 至少为 n 字节，必要时扩容，扩容后缓冲区类型将变为 shared
        @throws std::bad_alloc 内存分配失败
        @note 强异常安全：如果抛出异常，对象状态不变
    */
    std::span<std::uint8_t> prepare_front(std::size_t n);

    /*
        使 tail_room() 至少为 n 字节，必要时扩容，扩容后缓冲区类型将变为 shared
        @throws std::bad_alloc 内存分配失败
        @note 强异常安全：如果抛出异常，对象状态不变
    */
    std::span<std::uint8_t> prepare_back(std::size_t n);

    /*
         把 data() 向前移动 n，head_room() 减少 n
        @throws std::invalid_argument n 超过 head_room()
        @note 强异常安全：如果抛出异常，对象状态不变
    */
    void commit_front(std::size_t n);

    /*
         把 data() 向后移动 n，head_room() 增加 n
        @throws std::invalid_argument n 超过 size()
        @note 强异常安全：如果抛出异常，对象状态不变
    */
    void consume_front(std::size_t n);

    /*
        size() 增加 n，tail_room() 减少 n
        @throws std::invalid_argument n 超过 tail_room()
        @note 强异常安全：如果抛出异常，对象状态不变
    */
    void commit_back(std::size_t n);

    /*
        size() 减少 n, tail_room() 增加 n
        @throws std::invalid_argument n 超过 size()
        @note 强异常安全：如果抛出异常，对象状态不变
    */
    void consume_back(std::size_t n);

    /*
        获取大小为 head_room() 的缓冲区，缓冲区位于 data() 前
    */
    std::span<std::uint8_t> front_writable() noexcept {
        return front_writable(head_room());
    }

    /*
        获取大小为 n 的缓冲区，缓冲区位于 data() 前
    */
    std::span<std::uint8_t> front_writable(std::size_t n) noexcept;

    /*
        获取大小为 tail_room() 的缓冲区，缓冲区位于 data() + size() 后
    */
    std::span<std::uint8_t> back_writable() noexcept {
        return back_writable(tail_room());
    }

    /*
        获取大小为 n 的缓冲区，缓冲区位于 data() + size() 后
    */
    std::span<std::uint8_t> back_writable(std::size_t n) noexcept;

  private:
    friend struct io_buffer_pool;
    io_buffer();

    buffer_type _type{buffer_type::raw};
    union {
        // 不拥有所有权的
        std::span<std::uint8_t> _raw;
        shared_block *_shared;
    };

    std::size_t _offset{0};
    std::size_t _size{0};

    void ensure_shared(std::size_t required_capacity);

    io_buffer *_next{nullptr};
    io_buffer *_prev{nullptr};

    io_buffer_pool *_pool{nullptr};
    void *_info;
};

/*
    io_buffer 和 shared_block 的对象池。
    管理两个链表：空闲的 io_buffer 对象和空闲的 shared_block 内存块。
    注意：池销毁时，必须确保没有 io_buffer 或 shared_block 再引用本池
    （即所有从本池分配的缓冲区都已放回）。否则后续 release()
   调用将访问已销毁的池。
*/
struct io_buffer_pool {
    friend struct shared_block;
    friend struct io_buffer;

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
            _buffers = b->next();
            delete b;
        }
        while (_blocks) {
            auto block = _blocks;
            _blocks = block->next;
            shared_block::destroy(block);
        }
        _size = 0;
        _block_count = 0;
    }

    std::size_t size() const noexcept { return _size; }

    std::size_t max_size() const noexcept { return _max_size; }

    /*
        从池中获取缓冲区，如果池为空则创建新缓冲区
        @param head_room 需要的头部空间
        @param tail_room 需要的尾部空间
        @throws std::bad_alloc 内存分配失败
        @note 强异常安全：如果抛出异常，池状态不变（除了可能的内存分配失败情况）
              如果从池中取出缓冲区后 reshape
        失败，该缓冲区会被删除而不是返回池中
    */
    std::unique_ptr<io_buffer>
    get(std::size_t head_room = io_buffer::default_head_room(),
        std::size_t tail_room = io_buffer::default_tail_room());

    void put(std::unique_ptr<io_buffer> buffer) noexcept;

  private:
    const std::size_t _max_size;
    io_buffer *_buffers{nullptr};
    std::size_t _size{0};
    shared_block *_blocks{nullptr};
    std::size_t _block_count{0};

    /*
        从池中获取一个 shared_block，容量至少为 capacity。
         首先在空闲块链表中查找容量足够的块（首次适配）；如果找不到，分配新块。
        返回的块引用计数为1，pool指针指向本池。
        @throws std::bad_alloc 内存分配失败
        @note 强异常安全：如果分配失败，池状态不变（空闲链表不变）
    */
    shared_block *get_block(std::size_t capacity);

    /*
        将 shared_block 放回池的空闲链表。
        调用者必须确保 block->pool == this 且引用计数为0。
        @param block 要回收的块，必须非空
        @note noexcept，不抛出异常
    */
    void put_block(shared_block *block) noexcept;
};

struct io_buffer_ptr {
    io_buffer_ptr() noexcept {}
    io_buffer_ptr(io_buffer_pool *pool,
                  std::size_t head_room = io_buffer::default_head_room(),
                  std::size_t tail_room = io_buffer::default_tail_room())
        : _buffer(pool ? pool->get(head_room, tail_room).release()
                       : std::make_unique<io_buffer>(
                             io_buffer::make_shared(head_room + tail_room))
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

} // namespace asioice