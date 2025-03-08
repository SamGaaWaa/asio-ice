#pragma once

#include "async_queue.hpp"
#include "config.hpp"
#include "inline_task.hpp"
#include "shared_promise_v2.hpp"
#include "stun.hpp"

#include <boost/circular_buffer.hpp>
#include <boost/container/small_vector.hpp>
#include <boost/intrusive/set.hpp>

#if ASIOICE_USE_BOOST > 0
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include "exec/task.hpp"

#include <chrono>
#include <map>
#include <memory>

namespace ice::stun {

template <class Layer>
concept is_stream_layer = requires(Layer l, net::const_buffer buf) {
    l.async_write_some(buf, [](std::error_code, std::size_t) {});
};

static_assert(is_stream_layer<net::ip::tcp::socket>);

template <class Layer>
concept is_datagram_layer =
    !is_stream_layer<Layer> &&
    requires(Layer l, typename Layer::endpoint_type ep, net::const_buffer buf) {
        l.async_send_to(buf, ep, [](std::error_code, std::size_t) {});
    };

static_assert(is_datagram_layer<net::ip::udp::socket>);

template <class NextLayer = net::ip::udp::socket> class client_base {
  public:
    using next_layer_type = std::decay_t<NextLayer>;
    using endpoint_type = typename next_layer_type::endpoint_type;

    client_base(net::io_context &ctx, next_layer_type &sock) noexcept
        : _ctx(ctx), _sock(sock), _msg_pool(16), _local(sock.local_endpoint()) {
    }

    client_base(const client_base &) = delete;
    client_base &operator=(const client_base &) = delete;
    client_base(client_base &&) = delete;
    client_base &operator=(client_base &&) = delete;

    void stop() noexcept;
    bool is_running() const noexcept { return _running; }

    const auto &context() const noexcept { return _ctx; }
    auto &context() noexcept { return _ctx; }
    const auto &socket() const noexcept { return _sock; }
    auto &socket() noexcept { return _sock; }
    const auto &local_endpoint() const noexcept { return _local; }
    auto &message_pool() noexcept { return _msg_pool; }
    const auto &message_pool() const noexcept { return _msg_pool; }

  protected:
    net::io_context &_ctx;
    next_layer_type &_sock;
    endpoint_type _local;
    boost::circular_buffer<std::unique_ptr<stun::message>> _msg_pool;
    bool _running = true;
    shared_promise<void> _stop_promise{};
};

template <class NextLayer> class client {};

template <is_datagram_layer NextLayer>
class client<NextLayer>
    : public ice::stun::client_base<NextLayer>,
      public std::enable_shared_from_this<client<NextLayer>> {
  public:
    using next_layer_type = typename client_base<NextLayer>::next_layer_type;
    using endpoint_type = typename client_base<NextLayer>::endpoint_type;

    client(net::io_context &ctx, next_layer_type &sock) noexcept
        : client_base<NextLayer>(ctx, sock) {}

    bool dispatch(const endpoint_type &ep, const void *data, std::size_t size);

    inline_task<std::tuple<std::unique_ptr<stun::message>, endpoint_type>>
    request(const endpoint_type &ep, const stun::message &msg, auto timeout,
            std::size_t retries, std::shared_ptr<client<NextLayer>> self = {});

  private:
    struct transaction
        : std::enable_shared_from_this<transaction>,
          boost::intrusive::set_base_hook<
              boost::intrusive::link_mode<boost::intrusive::safe_link>> {
        transaction(const stun::message &msg, const endpoint_type &ep,
                    std::shared_ptr<client<next_layer_type>> c)
            : transaction_id(msg.transaction_id), endpoint(ep),
              _client(std::move(c)) {
            _buf.resize(msg.serialized_size());
            int ret = msg.write_to(_buf.data(), _buf.size());
            if (ret < 0 || ret != _buf.size()) {
                throw std::runtime_error("stun::message::write_to() failed");
            }
        }

        void run(std::chrono::milliseconds timeout, std::size_t max_retries);

        void stop() noexcept { _stop_promise.set_stopped(); }

        void set_done() noexcept { _done_promise.set_value(); }

        auto done() noexcept { return _done_promise.get_future(); }

        struct comparer {
            using type = std::array<uint8_t, 12>;
            const type &operator()(const transaction &t) const noexcept {
                return t.transaction_id;
            }
        };

        std::array<uint8_t, 12> transaction_id;
        endpoint_type endpoint;
        std::unique_ptr<stun::message> response{};
        endpoint_type response_from{};

      private:
        inline_task<void> retry(std::chrono::milliseconds timeout,
                                std::size_t max_retries,
                                std::shared_ptr<transaction> self);

        boost::container::small_vector<std::byte, 576> _buf;
        std::shared_ptr<client<next_layer_type>> _client;
        shared_promise<void> _done_promise{};
        shared_promise<void> _stop_promise{};
    }; // transaction

    using transaction_set = boost::intrusive::set<
        transaction,
        boost::intrusive::key_of_value<typename transaction::comparer>>;

    transaction_set _transactions{};
}; // client

template <is_stream_layer NextLayer>
class client<NextLayer>
    : public ice::stun::client_base<NextLayer>,
      public std::enable_shared_from_this<client<NextLayer>> {
  public:
    using next_layer_type = typename client_base<NextLayer>::next_layer_type;
    using endpoint_type = typename client_base<NextLayer>::endpoint_type;

    client(net::io_context &ctx, next_layer_type &sock) noexcept
        : client_base<NextLayer>(ctx, sock) {}

    bool dispatch(std::unique_ptr<stun::message> resp) noexcept;

    inline_task<std::unique_ptr<stun::message>>
    request(const stun::message &msg, auto timeout,
            std::shared_ptr<client<NextLayer>> self = {});

  private:
    struct transaction
        : boost::intrusive::set_base_hook<
              boost::intrusive::link_mode<boost::intrusive::safe_link>> {
        struct comparer {
            using type = std::array<uint8_t, 12>;
            const type &operator()(const transaction &t) const noexcept {
                return t.transaction_id;
            }
        };

        std::array<uint8_t, 12> transaction_id{};
        std::unique_ptr<stun::message> response{};
        shared_promise<void> done_promise{};
    };

    using transaction_set = boost::intrusive::set<
        transaction,
        boost::intrusive::key_of_value<typename transaction::comparer>>;

    transaction_set _transactions{};
};

} // namespace ice::stun

#include "stun_client.ipp"