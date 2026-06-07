#include "mdns.hpp"

#include "packet.hpp"
#include "shared_promise.hpp"
#include "inline_task.hpp"
#include "scope_guard.hpp"
#include "random.hpp"
#include "log.hpp"
#include "detached_with_data.hpp"

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

#include <exec/task.hpp>
#include <exec/when_any.hpp>
#include <exec/start_detached.hpp>

#include <boost/intrusive/set.hpp>
#include <boost/intrusive/list.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <atomic>
#include <optional>
#include <cassert>
#include <cstdlib>
#include <vector>
#include <ranges>

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
    inline_task<void> query_loop();

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
    bool is_probing = false
) {
    auto [begin, end] = queries.equal_range(name);
    for (; begin != end; ++begin) {
        if(begin->is_probing() == is_probing)
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
    exec::task<void> time_out_control();

    std::shared_ptr<server::impl_t> _server_impl;
    net::steady_timer _timer;
};

using service_ptr = std::shared_ptr<service_t>;
using service_set = boost::intrusive::list<service_t>;

struct server::impl_t: std::enable_shared_from_this<server::impl_t>
{
    impl_t(net::any_io_executor ex)noexcept :
        executor{ std::move(ex) },
        sock_s4{ executor, net::ip::udp::v4() },
        sock_r4{ executor, net::ip::udp::v4() }
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

    exec::task<std::expected<std::string, std::error_code>>
    queryAddr(std::string name, std::shared_ptr<server::impl_t> self = {});

    exec::task<std::expected<dns::record_t, std::error_code>>
    probe(std::string name);

    exec::task<std::expected<std::string, std::error_code>>
    publishAddr(std::string ip, int seconds = 3600, std::shared_ptr<server::impl_t> self = {});

    exec::task<void>
    remove(std::string name, std::shared_ptr<server::impl_t> self = {});

    net::any_io_executor executor;
    net::ip::udp::socket sock_s4;
    net::ip::udp::socket sock_r4;
    //std::optional<net::ip::udp::socket> sock_v6;
    query_set queries{};
    service_set services;
private:
    inline_task<void> server_loop();
    inline_task<void> receive_loop();
    const service_t *find_service_by_ip(std::string_view) const;

    utils::shared_promise<void> _stop;
    std::atomic_bool _stopped = false;
};

void query::start() {
    auto sched = asio2exec::scheduler{ _server_impl->executor };
    utils::detached_with_data(stdexec::starts_on(sched, stdexec::when_all(
        this->query_loop(),
        _cancel.get_future() | stdexec::continues_on(sched)
    ) | stdexec::into_variant()), this->shared_from_this());
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

inline_task<void> query::query_loop() {
    auto& impl = *this->_server_impl;
    utils::scope_guard on_exit([&]()noexcept{
        if(this->is_linked())
            impl.queries.erase(impl.queries.iterator_to(*this));
        this->_result.set_stopped(); // no effect if already stopped
    });

    dns::message_t msg;
    // Require a unicast response
    msg.questions.emplace_back(this->_question);
    msg.questions.back().cls |= (uint16_t{ 1 } << 15);

    net::steady_timer timer{ impl.executor };
    char buf[4096];

    const auto n = msg.write(buf, sizeof(buf));
    if (!n.has_value()) {
        CPPMDNS_IN_DEBUG{
            LOG_ERROR() << "Error while serializing query: " << n.error() << std::endl;
        }
        this->_result.set_value(std::unexpected(n.error()));
        co_return;
    }

    if (this->_result.empty()) {
        // no waiters
        co_return;
    }

    int first_delay = this->_is_probing ? utils::rand(0, 250) : utils::rand(20, 120);
    timer.expires_after(std::chrono::milliseconds{ first_delay });
    auto err = co_await timer.async_wait(asio2exec::use_sender);
    if (err) {
        this->_result.set_value(std::unexpected(err));
        co_return;
    }

    int query_interval = this->_is_probing ? 250 : 1000;
    std::size_t q_count = 0;
    while (!this->_result.empty()) {
        auto [err1, nsend1] = co_await impl.sock_s4.async_send_to(net::buffer(buf, *n), MDNS_ENDPOINT, asio2exec::use_sender);
        //auto [err2, nsend2] = co_await impl.sock_v6->async_send(net::buffer(buf, *n), asio2exec::use_sender);
        auto err2 = err1;
        if (err1 || err2) {
            CPPMDNS_IN_DEBUG{
                LOG_ERROR() << "Error while sending query: " << err1.message() << " " << err2.message() << std::endl;
            }
            this->_result.set_value(std::unexpected(err1 ? err1 : err2));
            co_return;
        }
        timer.expires_after(std::chrono::milliseconds(query_interval));
        if (!this->_is_probing){
            if (query_interval < 3600000)
                query_interval *= 2;
            if (query_interval > 3600000)
                query_interval = 3600000;
        }
        if (this->_result.empty())
            co_return;
        err = co_await timer.async_wait(asio2exec::use_sender);
        if (err) {
            this->_result.set_value(std::unexpected(err));
            co_return;
        }
        if (this->_is_probing && ++q_count == 3) {
            this->_result.set_value(std::unexpected(std::make_error_code(std::errc::timed_out)));
            co_return;
        }
    }

    co_return;
}

service_t::service_t(dns::record_t record, std::shared_ptr<server::impl_t> server_impl) :
    record{ std::move(record) },
    _server_impl{ std::move(server_impl) },
    _timer{ _server_impl->executor }
{}

void service_t::start() {
    auto sched = asio2exec::scheduler{ _server_impl->executor };
    utils::detached_with_data(stdexec::starts_on(sched, time_out_control()), shared_from_this());
}

void service_t::update_timeout(int seconds) {
    record.ttl = seconds;
    net::post(_server_impl->executor,
              [self = shared_from_this()] { self->_timer.cancel(); });
}

exec::task<void> service_t::time_out_control() {
    utils::scope_guard on_exit([&]()noexcept {
        if (this->is_linked())
            this->_server_impl->services.erase(this->_server_impl->services.iterator_to(*this));
    });
    
    do {
        this->_timer.expires_after(std::chrono::seconds{ this->record.ttl });
        co_await (this->_timer.async_wait(asio2exec::use_sender) | stdexec::stopped_as_optional());
    } while (this->record.ttl > 0);

    //TODO: Say goodbye
}

exec::task<std::expected<std::string, std::error_code>>
server::impl_t::queryAddr(std::string name, std::shared_ptr<server::impl_t> self)
{
    if (_stopped) {
        co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }
    co_await stdexec::schedule(asio2exec::scheduler{ executor });
    if(name.empty())
        co_return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    if (!name.ends_with(".local")) {
        name += ".local";
    }
    if (auto it = std::ranges::find_if(this->services, [&name](const auto& s) {
        return s.record.name == name;
    }); it != this->services.end()) {
        const auto& r = it->record;
        auto type = dns::get_record_type(r.data);
        assert(type == dns::record_type::A || type == dns::record_type::AAAA);
        if (type == dns::record_type::A) {
            co_return net::ip::address_v4{ std::get<dns::rdata::a>(r.data) }.to_string();
        }
        co_return net::ip::address_v6{ std::get<dns::rdata::aaaa>(r.data) }.to_string();
    }
    // Find query
    auto q = find_match_query(queries, name);
    if (q) {

    }
    else {
        // Make a query
        q = query::make_query(
            std::string{ name },
            dns::record_type::ANY,
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
    if (type != dns::record_type::A && type != dns::record_type::AAAA) {
        CPPMDNS_IN_DEBUG{
            LOG_ERROR() << "Unexpected record type: " << type << '\n';
        }
        co_return std::unexpected(std::error_code((int)error::invalid_result, mdns_category()));   
    }
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
    auto q = find_match_query(queries, name, true);
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

static std::string get_uuid() {
    static thread_local boost::uuids::random_generator gen;
    boost::uuids::uuid id = gen();
    return boost::uuids::to_string(id); 
}

exec::task<std::expected<std::string, std::error_code>>
server::impl_t::publishAddr(std::string ip, int seconds, std::shared_ptr<server::impl_t> self)
{
    if (_stopped) {
        co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }
    co_await stdexec::schedule(asio2exec::scheduler{ executor });

    if (auto srv = this->find_service_by_ip(ip); srv != nullptr) {
        co_return srv->record.name;
    }

    dns::record_t record{
        .name = get_uuid() + ".local",
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
        co_return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }
    //TODO: Probe
    // {
    //     auto other = co_await probe(service->record.name);
    //     if (other)
    //         co_return std::error_code((int)error::service_already_exists, mdns_category());
    // }
    service->start();
    services.push_back(*service);
    co_return service->record.name;
}

exec::task<void>
server::impl_t::remove(std::string name, std::shared_ptr<server::impl_t> self)
{
    if (_stopped) {
        co_return;
    }
    co_await stdexec::schedule(asio2exec::scheduler{ executor });
    for (auto& s : services) {
        if(s.record.name == name)
            s.stop();
    }
}

void server::impl_t::start() {
    auto sched = asio2exec::scheduler{ executor };
    utils::detached_with_data(stdexec::starts_on(sched, stdexec::when_all(
        server_loop(),
        receive_loop(),
        _stop.get_future() | stdexec::continues_on(sched)
    ) | stdexec::into_variant()), this->shared_from_this());
}

inline_task<void> server::impl_t::server_loop() {
    char buf[4096];
    utils::scope_guard on_exit([&]()noexcept {
        this->stop();
    });

    while (true) {
        net::ip::udp::endpoint remote;
        auto [err, n] = co_await this->sock_r4.async_receive_from(net::buffer(buf, sizeof(buf)), remote, asio2exec::use_sender);
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
                auto local_ep = this->sock_r4.local_endpoint();
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
                auto [begin, end] = this->queries.equal_range(answer.name);
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
                for (const auto& service : this->services) {
                    if (service.record.name == question.name && 
                        (question.type == dns::record_type::ANY || service.record.type() == question.type)) {
                        unicast_resp.answers.push_back(service.record);
                    }
                }
            else
                for (const auto& service : this->services) {
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
            std::tie(err, n) = co_await this->sock_s4.async_send_to(net::buffer(buf, *len), MDNS_ENDPOINT, asio2exec::use_sender);
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
            std::tie(err, n) = co_await this->sock_s4.async_send_to(net::buffer(buf, *len), remote, asio2exec::use_sender);
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
inline_task<void> server::impl_t::receive_loop() 
{
    char buf[4096];
    utils::scope_guard on_exit([&]()noexcept {
        this->stop();
    });

    while (true) {
        net::ip::udp::endpoint remote;
        auto [err, n] = co_await this->sock_s4.async_receive_from(net::buffer(buf, sizeof(buf)), remote, asio2exec::use_sender);
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
            auto [begin, end] = this->queries.equal_range(answer.name);
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

const service_t *server::impl_t::find_service_by_ip(std::string_view ip) const {
    for (const auto& s: this->services) {
        const auto& r = s.record;
        const auto& addr = r.data;
        auto type = dns::get_record_type(addr);
        assert(type == dns::record_type::A || type == dns::record_type::AAAA);

        std::string srv_ip;
        if (type == dns::record_type::A)
            srv_ip = net::ip::address_v4{ std::get<dns::rdata::a>(addr) }.to_string();
        else
            srv_ip = net::ip::address_v6{ std::get<dns::rdata::aaaa>(r.data) }.to_string();
        if (srv_ip == ip)
            return &s;
    }
    return nullptr;
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

server::server(net::any_io_executor ex):
    _impl{std::make_shared<server::impl_t>(std::move(ex))}
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
server::query(std::string name) {
    if (!_impl) {
        CPPMDNS_IN_DEBUG{
            LOG_ERROR() << "Server is stopped" << '\n';
        }
        throw std::runtime_error("Server is stopped");
    }
    std::lock_guard lk{_mtx};
    return _impl->queryAddr(std::move(name), _impl);
}

exec::task<std::expected<std::string, std::error_code>>
server::publish(std::string ip, int seconds) {
    if (!_impl) {
        CPPMDNS_IN_DEBUG{
            LOG_ERROR() << "Server is stopped" << '\n';
        }
        throw std::runtime_error("Server is stopped");
    }
    std::lock_guard lk{ _mtx };
    return _impl->publishAddr(std::move(ip), seconds, _impl);
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

net::any_io_executor server::get_executor() const noexcept {
    return _impl->executor;
}

} // namespace mdns