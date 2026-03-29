#include "io_buffer2.hpp"

#include <cassert>
#include <cstring>
#include <iostream>

namespace ice {

void test_basic() {
    // 测试 raw 缓冲区
    char raw_data[100] = {0};
    io_buffer buf = io_buffer::make_raw(raw_data, sizeof(raw_data), 10, 5);
    assert(buf.type() == io_buffer::buffer_type::raw);
    assert(buf.capacity() == 100);
    assert(buf.size() == 5);
    assert(buf.head_room() == 10);
    assert(buf.tail_room() == 85);

    // 写入数据
    std::memcpy(buf.data(), "hello", 5);
    assert(std::memcmp(raw_data + 10, "hello", 5) == 0);

    // 测试 raw 缓冲区在 prepare_front 时会转换为 shared（因为不能移动共享数据）
    buf.prepare_front(20); // 需要更多头部空间，但尾部空间足够
    assert(buf.type() ==
           io_buffer::buffer_type::shared); // raw 类型会转换为 shared
    assert(buf.head_room() == 20);
    assert(buf.size() == 5);
    assert(std::memcmp(buf.data(), "hello", 5) == 0);

    // 测试 shared 缓冲区
    io_buffer shared_buf = io_buffer::make_shared(100);
    assert(shared_buf.type() == io_buffer::buffer_type::shared);
    assert(shared_buf.capacity() == 100);
    assert(shared_buf.size() == 0);

    // 测试克隆
    io_buffer cloned = buf.clone();
    assert(cloned.type() == io_buffer::buffer_type::shared);
    assert(cloned.size() == 5);
    assert(std::memcmp(cloned.data(), "hello", 5) == 0);

    // 测试 commit/consume
    buf.clear();
    buf.prepare_back(10);
    std::memcpy(buf.back_writable(10).data(), "1234567890", 10);
    buf.commit_back(10);
    assert(buf.size() == 10);
    assert(std::memcmp(buf.data(), "1234567890", 10) == 0);

    buf.consume_front(3);
    assert(buf.size() == 7);
    assert(std::memcmp(buf.data(), "4567890", 7) == 0);

    buf.consume_back(2);
    assert(buf.size() == 5);
    assert(std::memcmp(buf.data(), "45678", 5) == 0);

    std::cout << "test_basic passed\n";
}

void test_raw_buffer_conversion() {
    // 测试 raw 缓冲区在 prepare 时会转换为 shared（因为不能移动共享数据）
    char raw_data[50] = {0};
    io_buffer buf = io_buffer::make_raw(raw_data, sizeof(raw_data), 10, 10);
    std::memcpy(buf.data(), "abcdefghij", 10);

    // 头部空间不足，但尾部空间足够移动数据
    // raw 类型不能移动数据，会转换为 shared
    std::size_t initial_head = buf.head_room();
    std::size_t initial_tail = buf.tail_room();
    buf.prepare_front(20); // 需要 10 字节更多头部空间
    assert(buf.type() ==
           io_buffer::buffer_type::shared); // raw 类型会转换为 shared
    assert(buf.head_room() == 20);
    assert(buf.size() == 10);
    // 尾部空间计算：新容量会大于原容量，因为分配了新缓冲区
    assert(std::memcmp(buf.data(), "abcdefghij", 10) == 0);

    // 测试另一个 raw 缓冲区 prepare_back 也会转换
    char raw_data2[50] = {0};
    io_buffer buf2 = io_buffer::make_raw(raw_data2, sizeof(raw_data2), 10, 10);
    std::memcpy(buf2.data(), "ABCDEFGHIJ", 10);
    buf2.prepare_back(31); // 需要更多尾部空间（当前30，需要31）
    assert(buf2.type() ==
           io_buffer::buffer_type::shared); // raw 类型会转换为 shared
    assert(buf2.tail_room() >= 31);         // 至少有 31 字节尾部空间
    assert(buf2.size() == 10);
    assert(std::memcmp(buf2.data(), "ABCDEFGHIJ", 10) == 0);

    std::cout << "test_raw_buffer_conversion passed\n";
}

void test_expansion_conversion() {
    // 测试当空间不足时 raw 转换为 shared
    char raw_data[20] = {0};
    io_buffer buf = io_buffer::make_raw(raw_data, sizeof(raw_data), 5, 10);
    std::memcpy(buf.data(), "0123456789", 10);

    // 需要更多空间，但 raw 缓冲区无法扩容，应转换为 shared
    buf.prepare_front(15); // 需要 10 字节更多头部空间，但尾部空间不足
    assert(buf.type() == io_buffer::buffer_type::shared); // 应转换为 shared
    assert(buf.head_room() == 15);
    assert(buf.size() == 10);
    assert(std::memcmp(buf.data(), "0123456789", 10) == 0);

    std::cout << "test_expansion_conversion passed\n";
}

void test_swap_and_move() {
    io_buffer buf1 = io_buffer::make_shared(50);
    std::memcpy(buf1.back_writable(5).data(), "hello", 5);
    buf1.commit_back(5);

    io_buffer buf2 = io_buffer::make_shared(30);
    std::memcpy(buf2.back_writable(3).data(), "abc", 3);
    buf2.commit_back(3);

    buf1.swap(buf2);
    assert(buf1.size() == 3);
    assert(buf2.size() == 5);
    assert(std::memcmp(buf1.data(), "abc", 3) == 0);
    assert(std::memcmp(buf2.data(), "hello", 5) == 0);

    // 测试移动构造
    io_buffer buf3(std::move(buf1));
    assert(buf3.size() == 3);
    assert(buf1.size() == 0); // 移动后为空

    // 测试移动赋值
    io_buffer buf4 = io_buffer::make_shared(1); // 临时缓冲区，将被移动赋值覆盖
    buf4 = std::move(buf2);
    assert(buf4.size() == 5);
    assert(buf2.size() == 0);

    std::cout << "test_swap_and_move passed\n";
}

void test_shared_buffer_safety() {
    // 测试共享缓冲区安全：当多个 io_buffer 共享同一数据时，prepare
    // 不应影响其他共享者
    io_buffer buf1 = io_buffer::make_shared(100);
    std::memcpy(buf1.back_writable(10).data(), "0123456789", 10);
    buf1.commit_back(10);

    // 创建共享副本
    io_buffer buf2 = buf1; // 拷贝构造，增加引用计数
    assert(buf1.type() == io_buffer::buffer_type::shared);
    assert(buf2.type() == io_buffer::buffer_type::shared);
    assert(std::memcmp(buf1.data(), "0123456789", 10) == 0);
    assert(std::memcmp(buf2.data(), "0123456789", 10) == 0);

    // buf1 调用 prepare_front，由于是共享缓冲区，应分配新缓冲区
    buf1.prepare_front(20);
    assert(buf1.type() == io_buffer::buffer_type::shared);
    assert(buf1.head_room() == 20);
    assert(buf1.size() == 10);
    // buf1 的数据应该保持不变
    assert(std::memcmp(buf1.data(), "0123456789", 10) == 0);

    // buf2 应该仍然有原来的数据，不受 buf1 的 prepare 影响
    assert(buf2.type() == io_buffer::buffer_type::shared);
    assert(buf2.size() == 10);
    assert(std::memcmp(buf2.data(), "0123456789", 10) == 0);

    std::cout << "test_shared_buffer_safety passed\n";
}

void test_reshape() {
    // 测试 reshape 功能
    io_buffer buf = io_buffer::make_shared(100);
    // 初始 head_room=0, tail_room=100, size=0
    assert(buf.head_room() == 0);
    assert(buf.tail_room() == 100);

    // reshape 到 head_room=20, tail_room=30
    buf.reshape(20, 30);
    std::cout << "DEBUG reshape: capacity=" << buf.capacity()
              << " head_room=" << buf.head_room()
              << " tail_room=" << buf.tail_room() << " size=" << buf.size()
              << std::endl;
    assert(buf.head_room() == 20);
    assert(buf.tail_room() >= 30);
    assert(buf.capacity() >= 50); // 至少 50

    // 写入数据
    std::memcpy(buf.back_writable(10).data(), "1234567890", 10);
    buf.commit_back(10);
    assert(buf.size() == 10);

    // reshape 到更大的 head_room，但容量足够，应该移动数据
    buf.reshape(40, 30);
    std::cout << "DEBUG reshape2: head_room=" << buf.head_room()
              << " tail_room=" << buf.tail_room() << std::endl;
    assert(buf.head_room() == 40);
    assert(buf.tail_room() >= 30);
    assert(buf.size() == 10);
    assert(std::memcmp(buf.data(), "1234567890", 10) == 0);

    // 共享缓冲区，引用计数>1 时 reshape 应该分配新缓冲区
    io_buffer buf2 = buf; // 共享
    buf.reshape(10, 10); // 需要移动数据，但引用计数>1，应分配新缓冲区
    assert(buf.head_room() == 10);
    assert(buf.tail_room() >= 10);
    assert(buf.size() == 10);
    assert(std::memcmp(buf.data(), "1234567890", 10) == 0);
    // buf2 应该不变
    assert(buf2.size() == 10);
    assert(buf2.head_room() == 40); // 仍然是原来的偏移
    assert(buf2.tail_room() ==
           50); // tail_room = capacity - head_room - size = 100 - 40 - 10 = 50

    std::cout << "test_reshape passed\n";
}

void test_pool_and_ptr() {
    // 测试池和智能指针
    io_buffer_pool pool(2); // 最大容量 2

    // 从池中获取缓冲区
    auto buf1 = pool.get(10, 20);
    assert(buf1 != nullptr);
    assert(pool.size() == 0); // 池中已取走一个

    std::cout << "DEBUG: buf1 capacity=" << buf1->capacity()
              << " head_room=" << buf1->head_room()
              << " tail_room=" << buf1->tail_room() << " size=" << buf1->size()
              << std::endl;

    // 使用缓冲区
    std::memcpy(buf1->back_writable(5).data(), "hello", 5);
    buf1->commit_back(5);
    assert(buf1->size() == 5);
    std::cout << "DEBUG after commit: head_room=" << buf1->head_room()
              << " tail_room=" << buf1->tail_room() << std::endl;
    assert(buf1->head_room() == 10);
    assert(buf1->tail_room() == 15);

    // 放回池中
    pool.put(std::move(buf1));
    assert(buf1 == nullptr);
    assert(pool.size() == 1);

    // 再次获取
    auto buf2 = pool.get(5, 5);
    assert(buf2 != nullptr);
    assert(pool.size() == 0);
    // 缓冲区应该是之前放回的，但已被 reshape 为 head_room=5, tail_room=5
    std::cout << "DEBUG buf2: head_room=" << buf2->head_room()
              << " tail_room=" << buf2->tail_room() << " size=" << buf2->size()
              << std::endl;
    assert(buf2->head_room() == 5);
    assert(buf2->tail_room() >= 5);
    assert(buf2->size() == 0); // clear() 被调用

    // 测试 io_buffer_ptr
    io_buffer_ptr ptr(&pool, 30, 40);
    assert(ptr != nullptr);
    assert(ptr->head_room() == 30);
    assert(ptr->tail_room() >= 40);

    // 移动语义
    io_buffer_ptr ptr2 = std::move(ptr);
    assert(ptr == nullptr);
    assert(ptr2 != nullptr);

    // ptr2 析构时缓冲区应返回池中
    // 手动 reset 测试
    ptr2.reset();
    assert(ptr2 == nullptr);
    assert(pool.size() == 1); // 缓冲区回到池中

    std::cout << "test_pool_and_ptr passed\n";
}

} // namespace ice

int main() {
    try {
        ice::test_basic();
        ice::test_raw_buffer_conversion();
        ice::test_expansion_conversion();
        ice::test_swap_and_move();
        ice::test_shared_buffer_safety();
        ice::test_reshape();
        ice::test_pool_and_ptr();
        std::cout << "All io_buffer2 tests passed!\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Test failed: " << e.what() << "\n";
        return 1;
    }
}