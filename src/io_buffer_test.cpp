#include "io_buffer.hpp"

#include <chrono>
#include <iostream>

void test() {
    using namespace asioice;
    io_buffer b1;                // default constructor
    io_buffer b2(10);            // constructor with head room
    io_buffer b3(b2);            // copy constructor
    io_buffer b4(std::move(b2)); // move constructor
    io_buffer b5(10, 10);        // constructor with head and tail room

    b3.shrink_to_fit(); // shrink to fit
    b3.reshape(10, 10); // reshape
    assert(b3.size() == 0);

    b1.reshape(0, 0); // reshape to 0
    {
        std::string hello = "hello";
        std::string world = " world";
        auto buf = b1.prepare_back(world.size()); // prepare back
        std::copy(world.begin(), world.end(), (char *)buf.data());
        b1.commit_back(world.size());         // commit back
        buf = b1.prepare_front(hello.size()); // prepare front
        std::copy(hello.begin(), hello.end(), (char *)buf.data());
        b1.commit_front(hello.size()); // commit front
        assert(b1.size() == hello.size() + world.size());
        std::cout << std::string_view{(const char *)b1.data(), b1.size()}
                  << '\n';
        b1.consume_front(6);
        if (std::string_view{(const char *)b1.data(), b1.size()} != "world") {
            std::cout << "consume front failed\n";
        }
    }
}

void benchmark(int n) {
    using namespace asioice;
    io_buffer_pool pool(16);

    uint8_t *max_addr = 0;
    auto begin_time = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < n; ++i) {
        io_buffer_ptr ptr(&pool);
        // io_buffer_ptr ptr(nullptr);
        if (ptr->begin() > max_addr)
            max_addr = ptr->begin();
    }
    auto end_time = std::chrono::high_resolution_clock::now();
    auto dura = std::chrono::duration_cast<std::chrono::nanoseconds>(
        end_time - begin_time);
    std::cout << "max_addr: " << (uint64_t)max_addr << '\n'
              << "time: " << dura.count() << " ns\n"
              << "average: " << (double)dura.count() / n << " ns\n";
}

int main(int argc, char **argv) {
    test();
    benchmark(argc > 1 ? std::atoi(argv[1]) : 10000);
}