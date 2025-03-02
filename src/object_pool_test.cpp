#include "object_pool.hpp"

#include <iostream>
#include <stdexcept>

using namespace ice;

int main() {
    object_pool<int> pool;

    uint64_t total = 0;
    for (int i = 1; i <= 10000; ++i) {
        object_ptr<int> ptr = pool.create(i);
        total += *ptr;
        if (ptr.use_count() != 1) {
            throw std::runtime_error("use_count != 1");
        }
    }

    std::cout << "Total: " << total << '\n';
}