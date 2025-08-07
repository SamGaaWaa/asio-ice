#pragma once

#include <algorithm>
#include <cassert>
#include <ranges>
#include <stdexcept>
#include <iostream>
#include <boost/intrusive/set.hpp>
#include <boost/container/small_vector.hpp>

#include "config.hpp"
#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include "asio2exec.hpp"
#include "scope_guard.hpp"
#include "stop_when.hpp"
#include "shared_promise_v2.hpp"
#include "stun.hpp"
#include "task.hpp"
#include "receiver.hpp"

namespace ice::stun::impl {

template <class LowestLayer> struct datagram_client {
    using endpoint_type = typename LowestLayer::endpoint_type;

    datagram_client(net::io_context &ctx) noexcept : _ctx(ctx) {}

    datagram_client(const datagram_client &) = delete;
    datagram_client &operator=(const datagram_client &) = delete;
    datagram_client(datagram_client &&) = delete;
    datagram_client &operator=(datagram_client &&) = delete;

    void stop() noexcept;
    bool is_running() const noexcept { return !_transactions.empty(); }

    const auto &context() const noexcept { return _ctx; }
    auto &context() noexcept { return _ctx; }

    bool dispatch_response(const endpoint_type &ep, const void *data,
                           std::size_t size) noexcept;

    template <class Transport>
    ice::task<bool> request(Transport &transport, const endpoint_type &ep,
                            const stun::message &msg, endpoint_type &from,
                            stun::message &resp, std::size_t retries,
                            auto... self);

  private:
    struct transaction
        : boost::intrusive::set_base_hook<
              boost::intrusive::link_mode<boost::intrusive::auto_unlink>> {
        struct comparer {
            using type = std::array<uint8_t, 12>;
            const type &operator()(const transaction &t) const noexcept {
                return t.request.transaction_id;
            }
        };

        const stun::message &request;
        endpoint_type &response_from;
        stun::message &response;
        bool success{false};
        ice::shared_promise<void> done_promise{};
    };

    using transaction_set = boost::intrusive::set<
        transaction,
        boost::intrusive::key_of_value<typename transaction::comparer>,
        boost::intrusive::constant_time_size<false>>;

    struct response_receiver : ice::datagram_receiver<endpoint_type> {
        explicit response_receiver(datagram_client &self) noexcept
            : ice::datagram_receiver<endpoint_type>(), _self(self) {}

        bool datagram_received(io_buffer_ptr &buffer,
                               const endpoint_type &endpoint) override;

      private:
        datagram_client &_self;
    };

    net::io_context &_ctx;
    transaction_set _transactions{};
    ice::shared_promise<void> _stop_promise{};
};

} // namespace ice::stun::impl

#include "impl/datagram_stun_client.ipp"