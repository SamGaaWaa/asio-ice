#pragma once

#if __cpp_lib_flat_set > 202207L
#include <boost/container/small_vector.hpp>
#include <flat_set>
#else
#include <boost/container/flat_set.hpp>
#endif

namespace ice {

#if __cpp_lib_flat_set > 202207L
template <class Key, std::size_t N = 16, class Compare = std::less<Key>>
using small_set =
    std::flat_set<Key, Compare, boost::containers::small_vector<Key, N>>;
#else
template <class Key, std::size_t N = 16, class Compare = std::less<Key>>
using small_set = boost::container::flat_set<Key, Compare>;
#endif

} // namespace ice
