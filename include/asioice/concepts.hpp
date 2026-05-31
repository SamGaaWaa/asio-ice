#pragma once

#include "asioice/config.hpp"
#include "asioice/address.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/buffer.hpp>
#include <boost/asio/any_io_executor.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
#include <asio/any_io_executor.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include <stdexec/execution.hpp>

#include <span>
#include <concepts>
#include <type_traits>

namespace asioice {

struct __send_receiver {
    using receiver_concept = stdexec::receiver_t;
    // #if ASIOICE_USE_BOOST_ASIO
    void
    set_value(std::tuple<boost::system::error_code, std::size_t>) && noexcept {}
    void set_value(boost::system::error_code, std::size_t) && noexcept {}
    // #else
    void set_value(std::tuple<std::error_code, std::size_t>) && noexcept {}
    void set_value(std::error_code, std::size_t) && noexcept {}
    // #endif
    void set_error(std::exception_ptr) && noexcept {}
    void set_stopped() && noexcept {}
};

template <class T>
concept AsyncPacketTransport =
    requires(T *t, net::const_buffer data,
             std::span<const net::const_buffer> data_array,
             asioice::endpoint ep) {
        stdexec::connect(stdexec::starts_on(stdexec::inline_scheduler{},
                                            t->async_send_to(data, ep)),
                         __send_receiver{});
        stdexec::connect(stdexec::starts_on(stdexec::inline_scheduler{},
                                            t->async_send_to(data_array, ep)),
                         __send_receiver{});
        { t->get_executor() } -> std::convertible_to<net::any_io_executor>;
    };

template <class T>
concept AsyncPacketConnectionTransport =
    requires(T *t, net::const_buffer data,
             std::span<const net::const_buffer> data_array) {
        stdexec::connect(stdexec::starts_on(stdexec::inline_scheduler{},
                                            t->async_send(data)),
                         __send_receiver{});
        stdexec::connect(stdexec::starts_on(stdexec::inline_scheduler{},
                                            t->async_send(data_array)),
                         __send_receiver{});
        { t->get_executor() } -> std::convertible_to<net::any_io_executor>;
    };

} // namespace asioice