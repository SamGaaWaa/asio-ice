#pragma once

#include "config.hpp"
#include "receiver.hpp"

#if ASIOICE_USE_BOOST > 0
#include <boost/asio/io_context.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/io_context.hpp>
namespace ice {
namespace net = asio;
}
#endif

namespace ice {

template <class NextLayer, bool IsDatagram> struct stun_protocol {};

template <class NextLayer>
struct stun_protocol<NextLayer, true>
    : datagram_receiver<typename NextLayer::endpoint_type> {
    using next_layer_type = NextLayer;
    using endpoint_type = typename next_layer_type::endpoint_type;
    using stun_client_type = stun::client<next_layer_type, true>;

    stun_protocol(net::io_context &ctx,
                  std::shared_ptr<NextLayer> next_layer) noexcept
        : datagram_receiver<typename NextLayer::endpoint_type>(
              std::move(next_layer)),
          _client(std::make_shared<stun_client_type>(ctx)) {}

    next_layer_type &next_layer() noexcept {
        return this->template transport<next_layer_type>();
    }

    const next_layer_type &next_layer() const noexcept {
        return this->template transport<next_layer_type>();
    }

    auto &client() noexcept { return *_client; }

    const auto &client() const noexcept { return *_client; }

    ice::task<bool> request(const endpoint_type &ep, const stun::message &msg,
                            endpoint_type &from, stun::message &resp,
                            std::size_t retries, auto... self) {
        return _client->request(next_layer(), ep, msg, from, resp, retries,
                                std::move(self)...);
    }

    bool datagram_received(io_buffer_ptr &buffer,
                           const endpoint_type &endpoint) override {
        if (!buffer)
            return false;
        if (_client->dispatch_response(endpoint, buffer->data(),
                                       buffer->size()))
            return true;
        return false;
    }

  private:
    std::shared_ptr<stun_client_type> _client;
};

} // namespace ice