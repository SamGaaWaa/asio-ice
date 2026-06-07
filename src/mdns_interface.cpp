#include "asioice/config.hpp"
#include "asioice/mdns_interface.hpp"
#include "mdns.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <boost/asio/io_context.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <boost/asio/io_context.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include "asio2exec.hpp"

#include <thread>
#include <mutex>

namespace asioice {

struct mdns_impl final : mdns_interface {
    mdns_impl() : _server(_ctx.get_executor()) {
        _th = std::thread([this] { _ctx.run(); });
    }

    mdns_impl(const mdns_impl &) = delete;
    mdns_impl(mdns_impl &&) = delete;
    mdns_impl &operator=(const mdns_impl &) = delete;
    mdns_impl &operator=(mdns_impl &&) = delete;

    ~mdns_impl() {
        _server.stop();
        _th.join();
    }

    exec::task<net::ip::address> resolve(std::string_view mdns_name) override {
        auto ret = co_await _server.query(std::string{mdns_name});
        if (!ret)
            throw std::system_error(ret.error());
        co_return net::ip::make_address(*ret);
    }

    exec::task<std::string> publish(net::ip::address ip) override {
        auto ret = co_await _server.publish(ip.to_string());
        if (!ret)
            throw std::system_error(ret.error());
        co_return std::move(*ret);
    }

  private:
    net::io_context _ctx{};
    std::thread _th{};
    mdns::server _server;
};

std::shared_ptr<mdns_interface> default_mdns_interface() {
    static std::mutex mtx;
    static std::weak_ptr<mdns_interface> g_p;

    std::shared_ptr<mdns_interface> res{};
    {
        std::lock_guard lk{mtx};
        res = g_p.lock();
        if (!res) {
            res = std::make_shared<mdns_impl>();
            g_p = res;
        }
    }

    return res;
}

} // namespace asioice