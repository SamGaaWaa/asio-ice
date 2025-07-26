#include "mdns.hpp"

#include "packet.hpp"
#include "shared_promise_v2.hpp"
#include "inline_task.hpp"
#include "scope_guard.hpp"
#include "random.hpp"
#include "log.hpp"

#if CPPMDNS_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/multicast.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>
#else
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/ip/multicast.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/udp.hpp>
#endif // CPPMDNS_USE_BOOST_ASIO

#include "asio2exec.hpp"

#include "exec/task.hpp"
#include "exec/when_any.hpp"

#include <boost/intrusive/set.hpp>
#include <boost/intrusive/list.hpp>

#include <atomic>
#include <optional>
#include <cassert>
#include <cstdlib>
#include <vector>

static const auto MDNS_ADDR = mdns::net::ip::make_address_v4("224.0.0.251");
static constexpr uint16_t MDNS_PORT = 5353;
static const auto MDNS_ENDPOINT = mdns::net::ip::udp::endpoint{ MDNS_ADDR, MDNS_PORT };

namespace mdns{

const char *version()noexcept{
    return "cppmdns-0.0.1";
}

struct query :
    std::enable_shared_from_this<query>,
    boost::intrusive::set_base_hook<
        boost::intrusive::link_mode<boost::intrusive::safe_link>
    >
{
    query(
        std::string name, 
        dns::record_type type, 
        std::shared_ptr<server::impl_t> server_impl,
        bool is_probing = false
    ) :
        _question{ std::move(name), type, dns::record_class::INTERNET },
        _server_impl{std::move(server_impl)},
        _is_probing{is_probing}
    {
        if (!_server_impl) {
            CPPMDNS_IN_DEBUG{
                LOG_ERROR() << "server_impl is null\n";
            }
            throw std::runtime_error("server_impl is null");
        }
    }

    query(const query&) = delete;
    query& operator=(const query&) = delete;
    query(query&&) = delete;
    query& operator=(query&&) = delete;

    ~query();

    friend auto operator<=>(const query& lhs, const query& rhs)noexcept {
        return lhs._question.name <=> rhs._question.name;
    }

    static std::shared_ptr<query> 
    make_query(
        std::string name, 
        dns::record_type type, 
        std::shared_ptr<server::impl_t> server_impl,
        bool is_probing = false
    ){
        return std::make_shared<query>(std::move(name), type, std::move(server_impl), is_probing);
    }

    void start();

    void stop()noexcept {
        if(_stopped)
            return;
        _stopped = true;
        _cancel.set_stopped();
        _result.set_stopped();
    }

    auto get_future()noexcept {
        return _result.get_future();
    }

    dns::record_type type()const noexcept {
        return _question.type;
    }

    bool is_probing()const noexcept {
        return _is_probing;
    }

    void set_result(const dns::record_t& record);

    struct query_comparer {
        using type = std::string_view;
        std::string_view operator()(const query& q) const noexcept {
            return q._question.name;
        }
    };
private:
    static inline_task<void> query_loop(std::shared_ptr<query> self);

    dns::question_t _question;
    utils::shared_promise<std::expected<dns::record_t, std::error_code>> _result;
    utils::shared_promise<void> _cancel;
    std::shared_ptr<server::impl_t> _server_impl;
    bool _is_probing = false;
    bool _stopped = false;
};

using query_ptr = std::shared_ptr<query>;
using query_set = boost::intrusive::multiset<query, boost::intrusive::key_of_value<query::query_comparer>>;

static query_ptr find_match_query(
    query_set& queries, 
    const std::string_view& name, 
    dns::record_type type,
    bool is_probing = false
) {
    auto [begin, end] = queries.equal_range(name);
    for (; begin != end; ++begin) {
        if(begin->type() == type && begin->is_probing() == is_probing)
            return begin->shared_from_this();
    }
    return nullptr;
}

struct service_t :
    std::enable_shared_from_this<service_t>,
    boost::intrusive::list_base_hook<
        boost::intrusive::link_mode<boost::intrusive::safe_link>
    >
{
    service_t(dns::record_t record, std::shared_ptr<server::impl_t> server_impl);

    service_t(const service_t&) = delete;
    service_t& operator=(const service_t&) = delete;
    service_t(service_t&&) = delete;
    service_t& operator=(service_t&&) = delete;

    void start();

    void update_timeout(int seconds);

    void stop()noexcept {
        update_timeout(0);
    }

    dns::record_t record;
private:
    static exec::task<void> time_out_control(std::shared_ptr<service_t> self);

    std::shared_ptr<server::impl_t> _server_impl;
    net::steady_timer _timer;
};

using service_ptr = std::shared_ptr<service_t>;
using service_set = boost::intrusive::list<service_t>;

struct server::impl_t: std::enable_shared_from_this<server::impl_t>
{
    impl_t(net::io_context& c)noexcept :
        ctx{ c },
        sock_s4{ c, net::ip::udp::v4() },
        sock_r4{ c, net::ip::udp::v4() }
    {
        sock_s4.bind(net::ip::udp::endpoint(net::ip::udp::v4(), 0));
        {
            net::socket_base::reuse_address option{ true };
            sock_r4.set_option(option);
        }
        sock_r4.bind(net::ip::udp::endpoint(net::ip::udp::v4(), 5353));
        {
            net::ip::multicast::join_group option{ MDNS_ADDR };
            sock_r4.set_option(option);
        }
    }

    void start();
    void stop()noexcept;

    ~impl_t()noexcept {
        // stop();
    }

    exec::task<std::expected<std::string, std::error_code>>
    queryAddr(std::string name, bool is_v4, std::shared_ptr<server::impl_t> self = {});

    exec::task<std::expected<dns::record_t, std::error_code>>
    probe(std::string name);

    exec::task<std::error_code>
    publishAddr(std::string name, std::string ip, int seconds = 3600, std::shared_ptr<server::impl_t> self = {});

    exec::task<void>
    remove(std::string name, std::shared_ptr<server::impl_t> self = {});

    net::io_context& ctx;
    net::ip::udp::socket sock_s4;
    net::ip::udp::socket sock_r4;
    //std::optional<net::ip::udp::socket> sock_v6;
    query_set queries{};
    service_set services;
private:
    static inline_task<void> server_loop(std::shared_ptr<server::impl_t> self);
    static inline_task<void> receive_loop(std::shared_ptr<server::impl_t> self);

    utils::shared_promise<void> _stop;
    std::atomic_bool _stopped = false;
};

void query::start() {
    auto sched = asio2exec::scheduler{ _server_impl->ctx };
    stdexec::start_detached(stdexec::starts_on(sched, stdexec::when_all(
        query_loop(shared_from_this()),
        _cancel.get_future() | stdexec::continues_on(sched)
    ) | stdexec::into_variant()));
}

void query::set_result(const dns::record_t& record) {
    if (is_linked())
        _server_impl->queries.erase(_server_impl->queries.iterator_to(*this));
    _result.set_value(record);
    _cancel.set_stopped();
}

query::~query() {
    if (is_linked())
        _server_impl->queries.erase(_server_impl->queries.iterator_to(*this));
    // stop(); // Guarantee be called by the user
}

inline_task<void> query::query_loop(std::shared_ptr<query> q) {
    auto& impl = *q->_server_impl;
    utils::scope_guard on_exit([&]()noexcept{
        if(q->is_linked())
            impl.queries.erase(impl.queries.iterator_to(*q));
        q->_result.set_stopped(); // no effect if already stopped
    });

    dns::message_t msg;
    // Require a unicast response
    msg.questions.emplace_back(q->_question);
    msg.questions.back().cls |= (uint16_t{ 1 } << 15);

    net::steady_timer timer{ impl.ctx };
    char buf[4096];

    const auto n = msg.write(buf, sizeof(buf));
    if (!n.has_value()) {
        CPPMDNS_IN_DEBUG{
            LOG_ERROR() << "Error while serializing query: " << n.error() << std::endl;
        }
        q->_result.set_value(std::unexpected(n.error()));
        co_return;
    }

    int first_delay = q->_is_probing ? utils::rand(0, 250) : utils::rand(20, 120);
    timer.expires_after(std::chrono::milliseconds{ first_delay });
    auto err = co_await timer.async_wait(asio2exec::use_sender);
    if (err) {
        q->_result.set_value(std::unexpected(err));
        co_return;
    }

    int query_interval = q->_is_probing ? 250 : 1000;
    std::size_t q_count = 0;
    while (true) {
        auto [err1, nsend1] = co_await impl.sock_s4.async_send_to(net::buffer(buf, *n), MDNS_ENDPOINT, asio2exec::use_sender);
        //auto [err2, nsend2] = co_await impl.sock_v6->async_send(net::buffer(buf, *n), asio2exec::use_sender);
        auto err2 = err1;
        if (err1 || err2) {
            CPPMDNS_IN_DEBUG{
                LOG_ERROR() << "Error while sending query: " << err1.message() << " " << err2.message() << std::endl;
            }
            q->_result.set_value(std::unexpected(err1 ? err1 : err2));
            co_return;
        }
        timer.expires_after(std::chrono::milliseconds(query_interval));
        if (!q->_is_probing){
            if (query_interval < 3600000)
                query_interval *= 2;
            if (query_interval > 3600000)
                query_interval = 3600000;
        }
        err = co_await timer.async_wait(asio2exec::use_sender);
        if (err) {
            q->_result.set_value(std::unexpected(err));
            co_return;
        }
        if (q->_is_probing && ++q_count == 3) {
            q->_result.set_value(std::unexpected(std::make_error_code(std::errc::timed_out)));
            co_return;
        }
    }

    co_return;
}

service_t::service_t(dns::record_t record, std::shared_ptr<server::impl_t> server_impl) :
    record{ std::move(record) },
    _server_impl{ std::move(server_impl) },
    _timer{ _server_impl->ctx }
{}

void service_t::start() {
    auto sched = asio2exec::scheduler{ _server_impl->ctx };
    stdexec::start_detached(stdexec::starts_on(sched, time_out_control(shared_from_this())));
}

void service_t::update_timeout(int seconds) {
    record.ttl = seconds;
    net::post(_server_impl->ctx,
              [self = shared_from_this()] { self->_timer.cancel(); });
}

exec::task<void> service_t::time_out_control(std::shared_ptr<service_t> self) {
    auto& service = *self;
    utils::scope_guard on_exit([&]()noexcept {
        if (service.is_linked())
            service._server_impl->services.erase(service._server_impl->services.iterator_to(service));
    });
    
    do {
        service._timer.expires_after(std::chrono::seconds{ service.record.ttl });
        co_await (service._timer.async_wait(asio2exec::use_sender) | stdexec::stopped_as_optional());
    } while (service.record.ttl > 0);

    //TODO: Say goodbye
}

exec::task<std::expected<std::string, std::error_code>>
server::impl_t::queryAddr(std::string name, bool is_v4, std::shared_ptr<server::impl_t> self)
{
    if (_stopped) {
        co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }
    co_await stdexec::schedule(asio2exec::scheduler{ ctx });
    if(name.empty())
        co_return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    if (!name.ends_with(".local")) {
        name += ".local";
    }
    // Find query
    auto q = find_match_query(queries, name, is_v4 ? dns::record_type::A : dns::record_type::AAAA);
    if (q) {

    }
    else {
        // Make a query
        q = query::make_query(
            std::string{ name },
            is_v4 ? dns::record_type::A : dns::record_type::AAAA,
            self
        );
        queries.insert(*q);
        q->start();
    }
    auto res = co_await q->get_future();
    if (!res.has_value())
        co_return std::unexpected(res.error());
    const auto& addr = res->data;
    auto type = dns::get_record_type(addr);
    assert(type == dns::record_type::A || type == dns::record_type::AAAA && "Unexpected record type");
    try {
        if (type == dns::record_type::A) {
            co_return net::ip::address_v4{ std::get<dns::rdata::a>(addr) }.to_string();
        }
        co_return net::ip::address_v6{ std::get<dns::rdata::aaaa>(addr) }.to_string();
    }
    catch (const std::exception& e) {
        CPPMDNS_IN_DEBUG{
            LOG_ERROR() << "Error while parsing address: " << e.what() << std::endl;
        }
        co_return std::unexpected(std::error_code((int)error::invalid_result, mdns_category()));
    }
}

exec::task<std::expected<dns::record_t, std::error_code>>
server::impl_t::probe(std::string name)
{
    if (name.empty())
        co_return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    if (!name.ends_with(".local")) {
        name += ".local";
    }
    // Find query
    auto q = find_match_query(queries, name, dns::record_type::ANY, true);
    if (!q) {
        // Make a query
        q = query::make_query(
            std::string{ name },
            dns::record_type::ANY,
            shared_from_this(),
            true
        );
        queries.insert(*q);
        q->start();
    }
    co_return co_await q->get_future();
}

exec::task<std::error_code>
server::impl_t::publishAddr(std::string name, std::string ip, int seconds, std::shared_ptr<server::impl_t> self)
{
    if (_stopped) {
        co_return std::make_error_code(std::errc::operation_canceled);
    }
    co_await stdexec::schedule(asio2exec::scheduler{ ctx });

    dns::record_t record{
        .name = std::move(name),
        .cls = dns::record_class::INTERNET,
        .ttl = seconds
    };

    service_ptr service = std::make_shared<service_t>(std::move(record), self);
    try {
        auto addr = net::ip::make_address(ip);
        if (addr.is_v4()) {
            service->record.data.emplace<dns::rdata::a>(addr.to_v4().to_uint());
        }
        else {
            service->record.data.emplace<dns::rdata::aaaa>(addr.to_v6().to_bytes());
        }
    }
    catch (const std::exception& e) {
        co_return std::make_error_code(std::errc::invalid_argument);
    }
    if (auto it = std::find_if(services.begin(), services.end(), [&](const auto& s) {
        return s.record.name == service->record.name && 
            s.record.type() == service->record.type();
        }); it != services.end())
    {
        co_return std::error_code((int)error::service_already_exists, mdns_category());
    }
    //TODO: Probe
    {
        auto other = co_await probe(service->record.name);
        if (other)
            co_return std::error_code((int)error::service_already_exists, mdns_category());
    }
    service->start();
    services.push_back(*service);
    co_return{};
}

exec::task<void>
server::impl_t::remove(std::string name, std::shared_ptr<server::impl_t> self)
{
    if (_stopped) {
        co_return;
    }
    co_await stdexec::schedule(asio2exec::scheduler{ ctx });
    for (auto& s : services) {
        if(s.record.name == name)
            s.stop();
    }
}

void server::impl_t::start() {
    auto sched = asio2exec::scheduler{ ctx };
    stdexec::start_detached(stdexec::starts_on(sched, stdexec::when_all(
        server_loop(shared_from_this()),
        receive_loop(shared_from_this()),
        _stop.get_future() | stdexec::continues_on(sched)
    ) | stdexec::into_variant()));
}

inline_task<void> server::impl_t::server_loop(std::shared_ptr<server::impl_t> self) {
    auto& impl = *self;
    char buf[4096];
    utils::scope_guard on_exit([&]()noexcept {
        self->stop();
    });

    while (true) {
        net::ip::udp::endpoint remote;
        auto [err, n] = co_await impl.sock_r4.async_receive_from(net::buffer(buf, sizeof(buf)), remote, asio2exec::use_sender);
        if (err) {
            CPPMDNS_IN_DEBUG{
                LOG_ERROR() << "Server loop: Error while receiving query: " << err.message() << std::endl;
            }
            continue;
        }
        if (n == 0) {
            CPPMDNS_IN_DEBUG{
                LOG_ERROR() << "Received empty query" << std::endl;
            }
            continue;
        }
        //TODO: Check if it was send from a local network
        {
            CPPMDNS_IN_DEBUG{
                auto local_ep = impl.sock_r4.local_endpoint();
                LOG_INFO() << "Local endpoint: " << local_ep.address() << ':' << local_ep.port() << std::endl;
                LOG_INFO() << "Remote endpoint: " << remote.address() << ':' << remote.port() << std::endl;
            }
        }
        auto msg = dns::message_t::parse(buf, n);
        if (!msg.has_value()) {
            CPPMDNS_IN_DEBUG{
                LOG_ERROR() << "Received invalid query" << std::endl;
            }
            continue;
        }
        if (msg->is_response()) {
            CPPMDNS_IN_DEBUG{
                auto js = msg->to_json();
                LOG_ERROR() << "Received response: " << js.dump(2) << std::endl;
            }
            if (msg->answers.empty())
                continue;
            for (const auto& answer : msg->answers) {
                if(answer.type() != dns::record_type::A && 
                    answer.type() != dns::record_type::AAAA &&
                    answer.type() != dns::record_type::ANY)
                    continue;
                auto [begin, end] = impl.queries.equal_range(answer.name);
                for (; begin != end;) {
                    // TODO Think about this, is the iterator still valid?
                    auto& q = *begin++;
                    if (q.type() == answer.type() || q.type() == dns::record_type::ANY) {
                        q.set_result(answer);
                    }
                }
            }
            continue;
        }
        CPPMDNS_IN_DEBUG{
            auto js = msg->to_json();
            LOG_ERROR() << "Received query: " << js.dump(2) << std::endl;
        }
        if(msg->questions.empty())
            continue;

        dns::message_t multicast_resp;
        multicast_resp.header.flags.qr = 1;
        dns::message_t unicast_resp;
        unicast_resp.header.flags.qr = 1;

        for (const auto& question : msg->questions) {
            //if (question.type != dns::record_type::A && 
            //    question.type != dns::record_type::AAAA &&
            //    question.type != dns::record_type::ANY)
            //    continue;
            if(question.is_unicast())
                for (const auto& service : impl.services) {
                    if (service.record.name == question.name && 
                        (question.type == dns::record_type::ANY || service.record.type() == question.type)) {
                        unicast_resp.answers.push_back(service.record);
                    }
                }
            else
                for (const auto& service : impl.services) {
                    if (service.record.name == question.name && 
                        (question.type == dns::record_type::ANY || service.record.type() == question.type)) {
                        multicast_resp.answers.push_back(service.record);
                    }
                }
        }
        if (!multicast_resp.answers.empty()) {
            auto len = multicast_resp.write(buf, sizeof(buf));
            if (!len) {
                CPPMDNS_IN_DEBUG{
                    LOG_ERROR() << "Failed to serialize multicast response:" << len.error().message() << std::endl;
                }
                continue;
            }
            std::tie(err, n) = co_await impl.sock_s4.async_send_to(net::buffer(buf, *len), MDNS_ENDPOINT, asio2exec::use_sender);
            if (err) {
                CPPMDNS_IN_DEBUG{
                    LOG_ERROR() << "Error while sending multicast response: " << err.message() << std::endl;
                }
            }
        }
        if (!unicast_resp.answers.empty()) {
            auto len = unicast_resp.write(buf, sizeof(buf));
            if (!len) {
                CPPMDNS_IN_DEBUG{
                    LOG_ERROR() << "Failed to serialize unicast response:" << len.error().message() << std::endl;
                }
                continue;
            }
            std::tie(err, n) = co_await impl.sock_s4.async_send_to(net::buffer(buf, *len), remote, asio2exec::use_sender);
            if (err) {
                CPPMDNS_IN_DEBUG{
                    LOG_ERROR() << "Error while sending unicast response: " << err.message() << std::endl;
                }
            }
        }
    }
    co_return;
}

/*
    Receive unicast responses
*/
inline_task<void> server::impl_t::receive_loop(std::shared_ptr<server::impl_t> self) 
{
    auto& impl = *self;
    char buf[4096];
    utils::scope_guard on_exit([&]()noexcept {
        self->stop();
    });

    while (true) {
        net::ip::udp::endpoint remote;
        auto [err, n] = co_await impl.sock_s4.async_receive_from(net::buffer(buf, sizeof(buf)), remote, asio2exec::use_sender);
        if (err) {
            CPPMDNS_IN_DEBUG{
                LOG_ERROR() << "Receive loop: Error while receiving query: " << err.message() << std::endl;
            }
            continue;
        }
        if (n == 0) {
            CPPMDNS_IN_DEBUG{
                LOG_ERROR() << "Received empty query" << std::endl;
            }
            continue;
        }
        //TODO: Check if it was sent from a local network
        {

        }
        auto msg = dns::message_t::parse(buf, n);
        if (!msg.has_value()) {
            CPPMDNS_IN_DEBUG{
                LOG_ERROR() << "Received invalid query" << std::endl;
            }
            continue;
        }
        if (!msg->is_response()) {
            //
            continue;
        }
        CPPMDNS_IN_DEBUG{
            auto js = msg->to_json();
            LOG_ERROR() << "Receive loop: Received response: " << js.dump(2) << std::endl;
        }
        if (msg->answers.empty())
            continue;
        for (const auto& answer : msg->answers) {
            if (answer.type() != dns::record_type::A && 
                answer.type() != dns::record_type::AAAA &&
                answer.type() != dns::record_type::ANY)
                continue;
            auto [begin, end] = impl.queries.equal_range(answer.name);
            for (; begin != end;) {
                // TODO: Think about this, is this iterator still valid?
                auto& q = *begin++;
                if (q.type() == answer.type() || q.type() == dns::record_type::ANY) {
                    q.set_result(answer);
                }
            }
        }
    }
    co_return;
}

void server::impl_t::stop()noexcept {
    bool exp = false;
    if (!_stopped.compare_exchange_strong(exp, true)) {
        return;
    }
    for (auto& q : queries)
        q.stop();
    for (auto& s : services)
        s.stop();
    _stop.set_stopped();
}

server::server(net::io_context& ctx):
    _impl{std::make_shared<server::impl_t>(ctx)}
{
    _impl->start();
}

server::server(server&& other)noexcept:
    _impl(std::exchange(other._impl, nullptr))
{}

server& server::operator=(server&& other)noexcept {
    if (this != &other) {
        _impl = std::exchange(other._impl, nullptr);
    }
    return *this;
}

server::~server()noexcept{
    stop();
}

exec::task<std::expected<std::string, std::error_code>>
server::queryA(std::string name) {
    if (!_impl) {
        CPPMDNS_IN_DEBUG{
            LOG_ERROR() << "Server is stopped" << '\n';
        }
        throw std::runtime_error("Server is stopped");
    }
    std::lock_guard lk{_mtx};
    return _impl->queryAddr(std::move(name), true, _impl);
}

exec::task<std::expected<std::string, std::error_code>>
server::queryAAAA(std::string name) {
    if (!_impl) {
        CPPMDNS_IN_DEBUG{
            LOG_ERROR() << "Server is stopped" << '\n';
        }
        throw std::runtime_error("Server is stopped");
    }
    co_return{};
}

exec::task<std::error_code>
server::publish(std::string name, std::string ip, int seconds) {
    if (!_impl) {
        CPPMDNS_IN_DEBUG{
            LOG_ERROR() << "Server is stopped" << '\n';
        }
        throw std::runtime_error("Server is stopped");
    }
    std::lock_guard lk{ _mtx };
    return _impl->publishAddr(std::move(name), std::move(ip), seconds, _impl);
}

exec::task<void>
server::remove(std::string name)
{
    if (!_impl) {
        CPPMDNS_IN_DEBUG{
            LOG_ERROR() << "Server is stopped" << '\n';
        }
        throw std::runtime_error("Server is stopped");
    }
    std::lock_guard lk{ _mtx };
    return _impl->remove(std::move(name), _impl);
}

void server::stop()noexcept {
    if (_impl)
        _impl->stop();
}

} // namespace mdns