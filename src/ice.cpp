#include "ice.hpp"

#include <iostream>

namespace ice {

const char *version() { return "0.1.0"; }

void debug_test() {
  std::cout << "Debug test" << std::endl;
}

} // namespace ice