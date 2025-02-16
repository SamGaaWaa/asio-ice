#pragma once

#include "config.hpp"
#include "inline_task.hpp"
#include "packet.hpp"
#include "shared_promise_v2.hpp"

#include <boost/circular_buffer.hpp>
#include <boost/container/flat_map.hpp>

#if ASIOICE_USE_BOOST > 0
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include <functional>
#include <unordered_map>

namespace ice {

struct udp_connection;

struct udp_proxy : std::enable_shared_from_this<udp_proxy> {
    template <class Protocol>
    udp_proxy(net::io_context &ctx, const net::ip::udp::endpoint &local,
              Protocol protocol, std::size_t pkg_cache_size = 16)
        : _ctx(ctx), _local(local), _sock(ctx, protocol),
          _pkg_pool(pkg_cache_size) {
        _sock.set_option(net::socket_base::reuse_address(true));
        _sock.bind(_local);
    }

    udp_proxy(const udp_proxy &) = delete;
    udp_proxy(udp_proxy &&) = delete;
    udp_proxy &operator=(const udp_proxy &) = delete;
    udp_proxy &operator=(udp_proxy &&) = delete;

    ~udp_proxy() { stop(); }

    std::shared_ptr<udp_connection> connect(const net::ip::udp::endpoint &peer,
                                            std::size_t buf_size = 16);

    void start();
    void stop() noexcept;

    net::ip::udp::socket &socket() noexcept { return _sock; }

    const net::ip::udp::endpoint &local() const noexcept { return _local; }

    bool add(const net::ip::udp::endpoint peer, udp_connection *conn) {
        return _connections.try_emplace(peer, conn).second;
    }

    void remove(const net::ip::udp::endpoint &peer) {
        _connections.erase(peer);
    }

    boost::circular_buffer<packet> &packet_cache() noexcept {
        return _pkg_pool;
    }

    const boost::circular_buffer<packet> &packet_cache() const noexcept {
        return _pkg_pool;
    }

    /*
        @param bool(const net::ip::udp::endpoint&, ice::packet&)
                when filter return false, proxy drops this packet
    */
    template <class Func> void set_filter(Func &&func) {
        _filter = std::forward<Func>(func);
    }

  private:
    ice::inline_task<void> read_loop(std::shared_ptr<udp_proxy> self);

    struct peer_hasher_t {
        std::size_t
        operator()(const net::ip::udp::endpoint &peer) const noexcept {
            return std::hash<std::string_view>{}(std::string_view{
                reinterpret_cast<const char *>(peer.data()), peer.size()});
        }
    };

    struct peer_compare_t {
        bool operator()(const net::ip::udp::endpoint &x,
                        const net::ip::udp::endpoint &y) const noexcept {
            return std::string_view{reinterpret_cast<const char *>(x.data()),
                                    x.size()} <
                   std::string_view{reinterpret_cast<const char *>(y.data()),
                                    y.size()};
        }
    };

    // using connection_map_t = std::unordered_map<net::ip::udp::endpoint,
    // udp_connection*, peer_hasher_t>;
    using connection_map_t =
        boost::container::flat_map<net::ip::udp::endpoint, udp_connection *,
                                   peer_compare_t>;

    net::io_context &_ctx;
    net::ip::udp::endpoint _local;
    net::ip::udp::socket _sock;
    std::size_t _mtu = 1500;
    boost::circular_buffer<packet> _pkg_pool;
    connection_map_t _connections;
    std::function<bool(const net::ip::udp::endpoint &, ice::packet &)> _filter{
        nullptr};
    bool _started{false};
    ice::shared_promise<void> _stop_signal;
};

} // namespace ice