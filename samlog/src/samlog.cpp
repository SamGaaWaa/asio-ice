#include "samlog.hpp"

#include <cstdio>

namespace samlog {

void logger_interface::do_log(log_level l, std::string_view msg,
                              std::source_location loc) noexcept {
    if (l > log_level::info)
        std::printf("[%s][%s:%u]: %.*s", level_to_str(l), loc.file_name(),
                    loc.line(), static_cast<int>(msg.size()), msg.data());
    else
        std::printf("[%s]: %.*s", level_to_str(l), static_cast<int>(msg.size()),
                    msg.data());
}

std::shared_ptr<logger_interface> &logger_instance() noexcept {
    static thread_local std::shared_ptr<logger_interface> s_logger = nullptr;
    return s_logger;
}

} // namespace samlog