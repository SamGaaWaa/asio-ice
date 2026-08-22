#pragma once

#include <atomic>
#include <string_view>
#include <type_traits>
#include <memory>
#include <format>
#include <source_location>

namespace samlog {

enum class log_level : char {
    trace = 0,
    debug = 1,
    info = 2,
    warn = 3,
    error = 4,
    off = 5
};

constexpr const char *level_to_str(log_level l) {
    switch (l) {
    case log_level::trace:
        return "trace";
    case log_level::debug:
        return "debug";
    case log_level::info:
        return "info";
    case log_level::warn:
        return "warn";
    case log_level::error:
        return "error";
    case log_level::off:
        return "off";
    }
}

class logger_interface {
#ifdef NDEBUG
    std::atomic<log_level> _level{log_level::info};
#else
    std::atomic<log_level> _level{log_level::trace};
#endif
  public:
    struct __auto_log {
        logger_interface *logger;
        log_level l;
        std::source_location loc;

        void operator()(std::string_view msg) noexcept {
            logger->log(l, msg, loc);
        }

        template <class A, class... Args>
        void operator()(std::format_string<A, Args...> fmt, A &&a,
                        Args &&...args) {
            char buf[1024];
            const std::size_t n = std::formatted_size(
                fmt, std::forward<A>(a), std::forward<Args>(args)...);
            if (n > sizeof(buf))
                logger->log(l,
                            std::format(fmt, std::forward<A>(a),
                                        std::forward<Args>(args)...),
                            loc);
            else {
                std::format_to(buf, fmt, std::forward<A>(a),
                               std::forward<Args>(args)...);
                logger->log(l, std::string_view{buf, n}, loc);
            }
        }

        template <class MsgGen> int operator<<(MsgGen &&g) {
            if (logger && l >= logger->level()) {
                g(*this);
            }
            return 0;
        }
    };

    logger_interface() = default;
    logger_interface(log_level l) : _level{l} {}

    virtual ~logger_interface() {}

    log_level level() const noexcept {
        return _level.load(std::memory_order::relaxed);
    }

    void set_level(log_level l) noexcept {
        _level.store(l, std::memory_order::relaxed);
    }

    void
    log(log_level l, std::string_view msg,
        std::source_location loc = std::source_location::current()) noexcept {
        do_log(l, msg, loc);
    }

  private:
    virtual void do_log(log_level l, std::string_view msg,
                        std::source_location loc) noexcept;
};

inline auto __log_from_generator(
    logger_interface *logger, log_level l,
    std::source_location loc = std::source_location::current()) noexcept {
    return logger_interface::__auto_log{logger, l, loc};
}

std::shared_ptr<logger_interface> &logger_instance() noexcept;
inline void set_logger(std::shared_ptr<logger_interface> logger) {
    logger_instance() = std::move(logger);
}

#define SAMLOG_TRACE SAMLOG(samlog::log_level::trace)
#define SAMLOG_DEBUG SAMLOG(samlog::log_level::debug)
#define SAMLOG_INFO SAMLOG(samlog::log_level::info)
#define SAMLOG_WARN SAMLOG(samlog::log_level::warn)
#define SAMLOG_ERROR SAMLOG(samlog::log_level::error)

#define SAMLOG(level)                                                          \
    samlog::__log_from_generator(samlog::logger_instance().get(), (level))     \
        << [&]

} // namespace samlog