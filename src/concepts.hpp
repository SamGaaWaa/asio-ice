#pragma once

#include "config.hpp"
#include "address.hpp"

#include <stdexec/execution.hpp>

#include <span>
#include <concepts>
#include <type_traits>

namespace asioice {

struct __send_receiver {
    using receiver_concept = stdexec::receiver_t;
#if ASIOICE_USE_BOOST_ASIO
    void
    set_value(std::tuple<boost::system::error_code, std::size_t>) && noexcept {}
    void set_value(boost::system::error_code, std::size_t) && noexcept {}
#else
    void set_value(std::tuple<std::error_code, std::size_t>) && noexcept {}
    void set_value(std::error_code, std::size_t) && noexcept {}
#endif
    void set_error(std::exception_ptr) && noexcept {}
    void set_stopped() && noexcept {}
};

template <class T>
concept AsyncPacketTransport =
    requires(T *t, std::span<const uint8_t> data,
             std::span<std::span<const uint8_t>> data_array,
             asioice::endpoint ep) {
        stdexec::connect(stdexec::starts_on(stdexec::inline_scheduler{},
                                            t->async_send_to(data, ep)),
                         __send_receiver{});
        stdexec::connect(stdexec::starts_on(stdexec::inline_scheduler{},
                                            t->async_send_to(data_array, ep)),
                         __send_receiver{});
    };

template <class T>
concept AsyncPacketConnectionTransport =
    requires(T *t, std::span<const uint8_t> data,
             std::span<std::span<const uint8_t>> data_array) {
        stdexec::connect(stdexec::starts_on(stdexec::inline_scheduler{},
                                            t->async_send(data)),
                         __send_receiver{});
        stdexec::connect(stdexec::starts_on(stdexec::inline_scheduler{},
                                            t->async_send(data_array)),
                         __send_receiver{});
    };

} // namespace asioice