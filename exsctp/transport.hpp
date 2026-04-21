#pragma once

#include "./interface.hpp"

#include <memory>

namespace sctp {

template <IOInterface Interface = any_io_interface>
struct basic_transport {

};

using transport = basic_transport<>;

} // namespace sctp