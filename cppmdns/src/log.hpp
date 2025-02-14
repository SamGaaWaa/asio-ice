#pragma once

#include <iostream>
#include <source_location>

namespace __log_detail {
    std::ostream& log_stream(std::ostream& os, const std::source_location& sl);
}

#define LOG_INFO() LOG_STREAM(std::cout)
#define LOG_ERROR() LOG_STREAM(std::cerr)

#define LOG_STREAM(os) \
    [](std::ostream& oss)->std::ostream&{ \
        std::source_location sl = std::source_location::current(); \
        return __log_detail::log_stream(oss, sl); \
    }(os)