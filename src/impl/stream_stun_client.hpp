#pragma once

#include "config.hpp"
#include "shared_promise_v2.hpp"
#include "stun.hpp"
#include "task.hpp"

#include <boost/intrusive/set.hpp>

#if ASIOICE_USE_BOOST > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/write.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include <algorithm>
#include <iostream>
#include <stdexcept>

namespace ice::stun::impl {

template <class NextLayer> struct stream_client {
    using next_layer_type = NextLayer;
    using endpoint_type = typename next_layer_type::endpoint_type;

    stream_client(net::io_context &ctx, next_layer_type &sock) noexcept
        : _ctx(ctx), _sock(sock), _local(sock.local_endpoint()),
          _remote(sock.remote_endpoint()) {}

    stream_client(const stream_client &) = delete;
    stream_client &operator=(const stream_client &) = delete;
    stream_client(stream_client &&) = delete;
    stream_client &operator=(stream_client &&) = delete;

    void stop() noexcept;
    bool is_running() const noexcept { return _running; }

    const auto &context() const noexcept { return _ctx; }
    auto &context() noexcept { return _ctx; }
    const auto &next_layer() const noexcept { return _sock; }
    auto &next_layer() noexcept { return _sock; }
    const auto &local_endpoint() const noexcept { return _local; }
    const auto &remote_endpoint() const noexcept { return _remote; }

    bool dispatch(const void *data, std::size_t size) noexcept;

    ice::task<bool> request(const stun::message &msg, stun::message &resp,
                            auto timeout);

  private:
    struct transaction
        : boost::intrusive::set_base_hook<
              boost::intrusive::link_mode<boost::intrusive::auto_unlink>> {
        struct comparer {
            using type = std::array<uint8_t, 12>;
            const type &operator()(const transaction &t) const noexcept {
                return t.transaction_id;
            }
        };

        std::array<uint8_t, 12> transaction_id{};
        stun::message &response;
        bool success{false};
        ice::shared_promise<void> done_promise{};
    };

    using transaction_set = boost::intrusive::set<
        transaction,
        boost::intrusive::key_of_value<typename transaction::comparer>,
        boost::intrusive::constant_time_size<false>>;

    net::io_context &_ctx;
    next_layer_type &_sock;
    endpoint_type _local;
    endpoint_type _remote;
    bool _running = true;
    transaction_set _transactions{};
};

} // namespace ice::stun::impl

#include "impl/stream_stun_client.ipp"