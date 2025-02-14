#include "random.hpp"

#include <random>

namespace mdns::utils{

int rand(int min, int max){
    static thread_local std::random_device rd;
    static thread_local std::default_random_engine e(rd());
    std::uniform_int_distribution<int> dist(min, max);
    return dist(e);
}

} // namespace mdns::utils