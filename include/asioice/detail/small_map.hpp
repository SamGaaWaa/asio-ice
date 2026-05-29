#pragma once

#if __cpp_lib_flat_map > 202207L
#include <boost/container/small_vector.hpp>
#include <flat_map>
#else
#include <boost/container/flat_map.hpp>
#endif

namespace asioice {

#if __cpp_lib_flat_map > 202207L
template <class Key, class T, std::size_t N = 16,
          class Compare = std::less<Key>>
using small_map =
    std::flat_map<Key, T, Compare, boost::container::small_vector<Key, N>,
                  boost::container::small_vector<T, N>>;
#else
template <class Key, class T, std::size_t N = 16,
          class Compare = std::less<Key>>
using small_map = boost::container::flat_map<Key, T, Compare>;
#endif

} // namespace asioice