#pragma once

#include "async_queue.hpp"
#include "io_buffer.hpp"
#include "scope_guard.hpp"

#include <boost/intrusive/list_hook.hpp>

#include <memory>

namespace ice {

struct receiver_base {
    receiver_base() = default;
    receiver_base(const receiver_base &) = delete;
    receiver_base &operator=(const receiver_base &) = delete;
    receiver_base(receiver_base &&) = delete;
    receiver_base &operator=(receiver_base &&) = delete;
    virtual ~receiver_base() = default;
};

template <class Endpoint>
struct datagram_receiver
    : receiver_base,
      boost::intrusive::list_base_hook<
          boost::intrusive::link_mode<boost::intrusive::auto_unlink>> {
    using endpoint_type = Endpoint;

    datagram_receiver() noexcept = default;

    template <class Transport>
    datagram_receiver(std::shared_ptr<Transport> transport) {
        transport->add_receiver(*this);
        _transport = std::move(transport);
    }

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
    using base_type = datagram_receiver<endpoint_type>;

    template <class Transport>
    queue_datagram_receiver(
        std::shared_ptr<Transport> transport,
        std::size_t max = std::numeric_limits<std::size_t>::max())
        : datagram_receiver<endpoint_type>(std::move(transport)), _q(max) {}

    bool empty() const noexcept { return _q.empty(); }

    std::size_t size() const noexcept { return _q.size(); }

    auto async_pop() { return _q.async_pop_stoppable(); }

  private:
    virtual bool datagram_received(io_buffer_ptr &buffer,
                                   const endpoint_type &endpoint) override {
        _q.push(std::make_tuple(std::move(buffer), endpoint));
        return true;
    }

    ice::async_queue<std::tuple<io_buffer_ptr, endpoint_type>> _q;
};

template <class Endpoint>
inline bool dispatch_receivers(auto &receivers, io_buffer_ptr &buffer,
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
            return true;
    }
    return false;
}

} // namespace ice