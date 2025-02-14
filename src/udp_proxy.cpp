#include "udp_proxy.hpp"
#include "udp_connection.hpp"
#include "scope_guard.hpp"

#include <exec/when_any.hpp>

#if ASIOICE_USE_BOOST > 0
#define ASIO_TO_EXEC_USE_BOOST
#include "asio2exec.hpp"
namespace ice {
	namespace net = boost::asio;
}
#else
#include "asio2exec.hpp"
namespace ice {
	namespace net = asio;
}
#endif

#include <iostream>

namespace ice {

bool udp_connection::attach(udp_proxy& proxy) {
	if (this->_proxy.get() == &proxy)
		return true;
	if (proxy.add(peer(), this)) {
		detach();
		this->_proxy = proxy.shared_from_this();
		return true;
	}
	return false;
}

void udp_connection::detach()noexcept {
	if (this->_proxy) {
		this->_proxy->remove(peer());
		this->_proxy = nullptr;
	}
}

net::ip::udp::socket& udp_connection::socket() {
	if (!this->_proxy)
		throw std::runtime_error{ "proxy == nullptr" };
	return this->_proxy->socket();
}

std::shared_ptr<udp_connection> udp_proxy::connect(const net::ip::udp::endpoint& peer, std::size_t buf_size)
{
	if (_connections.find(peer) != _connections.end())
		return nullptr;
	auto conn = std::make_shared<udp_connection>(local(), peer, buf_size);
	conn->attach(*this);
	return conn;
}

void udp_proxy::start() {
	if (_started)
		return;
	_started = true;
	ice::utils::scope_guard on_error([this]()noexcept {
		_started = false;
	});
	asio2exec::scheduler_t sched(_ctx);
	stdexec::start_detached(
		stdexec::starts_on(
			sched,
			exec::when_any(
				read_loop(shared_from_this()),
				_stop_signal.get_future() | stdexec::continues_on(sched)
			)
		)
	);
	on_error.dismiss();
}

void udp_proxy::stop()noexcept {
	if (!_started)
		return;
	_started = false;
	_stop_signal.set_stopped();
}

ice::inline_task<void> udp_proxy::read_loop(std::shared_ptr<udp_proxy> self) {
	utils::scope_guard on_stopped([this]()noexcept {
		_sock.close();
		while (!_connections.empty()) {
			auto it = _connections.begin();
			it->second->close();
		}
		_started = false;
	});
	while (true) {
		net::ip::udp::endpoint ep;
		//TODO: get from a pool
		packet pkg;
		if (!packet_cache().empty()) {
			pkg = std::move(packet_cache().front());
			packet_cache().pop_front();
		}
		pkg.resize(_mtu);
		auto [err, n] = co_await _sock.async_receive_from(net::buffer(pkg.data(), pkg.size()), ep, asio2exec::use_sender);
		if (err) {
			ICE_IN_DEBUG{ std::cerr << "Read error\n"; };
			continue;
		}
		pkg.resize(n);
		if (_filter != nullptr && !_filter(ep, pkg)) {
			if (pkg.size() != 0)
				packet_cache().push_back(std::move(pkg));
			continue;
		}
		auto conn = _connections.find(ep);
		if (conn != _connections.end())
			conn->second->dispatch(std::move(pkg));
		else {
			ICE_IN_DEBUG{
				std::string str = ep.address().to_string() + ":" + std::to_string(ep.port());
				std::cout << "Data from unknown endpoint: " << str << '\n';
			}
			
		}
	}
}

} // namespace ice