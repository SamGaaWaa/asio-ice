#pragma once

#include "async_queue.hpp"
#include "io_buffer.hpp"
#include "scope_guard.hpp"

#include <boost/intrusive/list_hook.hpp>

#include <memory>

namespace ice {

template <class Endpoint>
struct datagram_receiver
    : boost::intrusive::list_base_hook<
          boost::intrusive::link_mode<boost::intrusive::auto_unlink>> {
    using endpoint_type = Endpoint;

    template <class Transport>
    datagram_receiver(std::shared_ptr<Transport> transport) {
        transport->add_receiver(*this);
        _transport = std::move(transport);
    }

    datagram_receiver(const datagram_receiver &) = delete;
    datagram_receiver &operator=(const datagram_receiver &) = delete;
    datagram_receiver(datagram_receiver &&) = delete;
    datagram_receiver &operator=(datagram_receiver &&) = delete;

    virtual ~datagram_receiver() { detach(); }

    template <class Transport> auto &transport() noexcept {
        return *static_cast<Transport *>(_transport.get());
    }

    template <class Transport> const auto &transport() const noexcept {
        return *static_cast<const Transport *>(_transport.get());
    }

    virtual bool datagram_received(io_buffer_ptr &buffer,
                                   const endpoint_type &endpoint) = 0;

    void detach() noexcept {
        if (is_linked()) {
            unlink();
            _transport.reset();
        }
    }

  private:
    std::shared_ptr<void> _transport;
};

template <class Endpoint>
struct queue_datagram_receiver : public datagram_receiver<Endpoint> {
    using endpoint_type = Endpoint;
    using base_type = datagram_receiver<Endpoint>;

    template <class Transport>
    queue_datagram_receiver(
        std::shared_ptr<Transport> transport,
        std::size_t max = std::numeric_limits<std::size_t>::max())
        : datagram_receiver<Endpoint>(std::move(transport)), _q(max) {}

    bool empty() const noexcept { return _q.empty(); }

    std::size_t size() const noexcept { return _q.size(); }

    auto async_pop() { return _q.async_pop_stoppable(); }

  private:
    virtual bool datagram_received(io_buffer_ptr &buffer,
                                   const endpoint_type &endpoint) override {
        _q.push(std::make_tuple(std::move(buffer), endpoint));
        return true;
    }

    ice::async_queue<std::tuple<io_buffer_ptr, Endpoint>> _q;
};

template <class Endpoint>
inline void dispatch_receivers(auto &receivers, io_buffer_ptr &buffer,
                               const Endpoint &endpoint) {
    using list_type = std::remove_reference_t<decltype(receivers)>;

    list_type receivers1;
    receivers.swap(receivers1);
    utils::scope_guard on_exit([&]() noexcept {
        if (!receivers1.empty())
            receivers.swap(receivers1);
    });

    list_type tmp;
    utils::scope_guard put_back([&]() noexcept {
        if (!tmp.empty())
            receivers1.splice(receivers1.begin(), tmp);
    });
    while (!receivers1.empty()) {
        auto &r = receivers1.front();
        receivers1.pop_front();
        tmp.push_back(r);
        if (r.datagram_received(buffer, endpoint))
            break;
    }
}

} // namespace ice