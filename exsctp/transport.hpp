#pragma once

#include "interface.hpp"
#include "impl/transport_impl2.hpp"

#include <memory>

namespace exsctp {

template <IOInterface Interface = any_io_interface>
struct basic_transport {
    using impl_type = impl::transport_impl<Interface>;

private:
    std::shared_ptr<impl_type> _impl;
};

using transport = basic_transport<>;

} // namespace exsctp