#include "error.hpp"

namespace mdns{
    const std::error_category& mdns_category()noexcept{
        static const mdns_error_category instance;
        return instance;
    }
}