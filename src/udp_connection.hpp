#pragma once

#include "config.hpp"
#include "async_queue.hpp"
#include "packet.hpp"
#include "udp_proxy.hpp"

#if ASIOICE_USE_BOOST > 0
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
#include <asio/ip/udp.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include <memory>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace ice {

class udp_connection : public std::enable_shared_from_this<udp_connection> {
  public:
    friend struct udp_proxy;

    udp_connection(const net::ip::udp::endpoint &local,
                   const net::ip::udp::endpoint &peer,
                   std::size_t max_buf_size = 16)
        : _q(max_buf_size), _local(local), _peer(peer) {}

    udp_connection(const udp_connection &) = delete;
    udp_connection &operator=(const udp_connection &) = delete;
    udp_connection(udp_connection &&) = delete;
    udp_connection &operator=(udp_connection &&) = delete;

    ~udp_connection() { detach(); }

    void dispatch(packet pkg) noexcept { _q.push(std::move(pkg)); }

    bool attach(udp_proxy &proxy);

    bool is_attached() const noexcept { return _proxy != nullptr; }

    void detach() noexcept;

    auto async_read() { return _q.async_pop_stoppable(); }

    auto async_read(packet &buf) {
        _proxy->packet_cache().push_back(std::move(buf));
        return _q.async_pop_stoppable();
        //|
        // stdexec::then([&](std::optional<packet> pkg)noexcept {
        //    if (!pkg)
        //        return false;
        //    buf = std::move(*pkg);
        //    return true;
        //});
    }

    template <class CompletionToken>
    auto async_send(net::const_buffer buf, CompletionToken &&token) {
        return socket().async_send_to(buf, peer(),
                                      std::forward<CompletionToken>(token));
    }

    std::size_t send(net::const_buffer buf) {
        return socket().send_to(buf, peer());
    }

    const net::ip::udp::endpoint &local() const noexcept { return _local; }

    const net::ip::udp::endpoint &peer() const noexcept { return _peer; }

    udp_proxy *proxy() noexcept { return _proxy.get(); }

    const udp_proxy *proxy() const noexcept { return _proxy.get(); }

    net::ip::udp::socket &socket();

    void close() noexcept {
        detach();
        _q.close();
    }

  private:
    async_queue<packet> _q;
    net::ip::udp::endpoint _local;
    net::ip::udp::endpoint _peer;
    std::shared_ptr<udp_proxy> _proxy;
};

} // namespace ice