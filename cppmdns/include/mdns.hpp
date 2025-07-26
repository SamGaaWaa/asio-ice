#pragma once

#include <string>
#include <memory>
#include <expected>
#include <mutex>

#include "error.hpp"
#include "config.hpp"

#if CPPMDNS_USE_BOOST_ASIO > 0
    #include <boost/asio/io_context.hpp>
    namespace mdns{
        namespace net = boost::asio;
    }
#else
    #include <asio/io_context.hpp>
    namespace mdns{
        namespace net = asio;
    }
#endif // CPPMDNS_USE_BOOST_ASIO

#include "exec/task.hpp"

namespace mdns {
    
const char *version()noexcept;

struct server{
    server(net::io_context& ctx);

    server(const server&) = delete;
    server& operator=(const server&) = delete;

    server(server&&) noexcept;
    server& operator=(server&&) noexcept;

    ~server() noexcept;

    exec::task<std::expected<std::string, std::error_code>>
    queryA(std::string name);

    exec::task<std::expected<std::string, std::error_code>>
    queryAAAA(std::string name);

    exec::task<std::error_code>
    publish(std::string name, std::string ip, int seconds = 3600);

    exec::task<void>
    remove(std::string name);

    void stop()noexcept;
private:
    struct impl_t;
    friend struct query;
    friend struct service_t;

    std::shared_ptr<impl_t> _impl;
    std::mutex _mtx{};
};
    
}
