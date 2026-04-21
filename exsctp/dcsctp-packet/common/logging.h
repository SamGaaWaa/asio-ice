#pragma once

#ifndef NDEBUG
#include <iostream>
#endif

namespace __rtc_logging_detail {
    struct nullstream {
        template <typename T>
        nullstream& operator<<(const T&) { return *this; }
    };

#ifndef NDEBUG
    struct cond_stream {
        cond_stream() = default;

        void set_condition(bool cond) { condition_ = cond; }

        cond_stream& operator<<(const auto& value) {
            if (!condition_) {
                std::cerr << value;
            }
            return *this;
        }
    private:
        bool condition_{true};        
    };
#endif

    auto& get_stream(bool cond) {
#ifndef NDEBUG
        static thread_local cond_stream s;
        s.set_condition(cond);
        return s;
#else
        static nullstream s;
        return s;
#endif
    }
}

#define SCTP_DLOG_WARNING() \
    (::__rtc_logging_detail::get_stream(true) << __FILE__ << ":" << __LINE__ << ": WARNING: ") 

#define SCTP_DCHECK(condition) \
    (::__rtc_logging_detail::get_stream(condition) << __FILE__ << ":" << __LINE__ << ": WARNING: ") 
