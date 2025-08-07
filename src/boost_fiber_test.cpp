#include "boost_context/context.hpp"

#include <iostream>
#include <chrono>

namespace bctx = ice::boost_context;

void test(int n) {
    auto ctx = bctx::make_context([n] {
        for (int i = 0; i < n; ++i) {
            // std::cout << i << '\n';
            bctx::context::yield();
        }
        // std::cout << "fiber end\n";
    });
    std::cout << "Begin\n";
    auto begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < n; ++i) {
        ctx->resume();
    }
    ctx->resume();
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Finish\n";

    auto duration =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "Time: " << duration.count() << " ns\n"
              << "Average: " << duration.count() / n << " ns\n";
}

int main() { test(1000000); }