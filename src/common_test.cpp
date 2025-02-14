#include "config.hpp"
#include "ice.hpp"
#include "candidate.hpp"

#if ASIOICE_USE_BOOST > 0
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/host_name.hpp>
namespace ice {
	namespace net = boost::asio;
}
#else
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/ip/host_name.hpp>
namespace ice {
	namespace net = asio;
}
#endif

#include <iostream>
#include <concepts>
#include <vector>
#include <string>

struct utf8_iterator {
	constexpr utf8_iterator(char *p = nullptr)noexcept:
		_ptr(p)
	{ }

	constexpr char32_t operator*()const noexcept {
		return {};
	}
private:
	char* _ptr;
};

void get_local_candidate_test() {
	ice::debug_test();
}

void candidate_test() {
	using namespace ice;
    candidate c(
		ice::candidate_foundation(candidate_type::host, "udp", net::ip::address::from_string("127.0.0.1")),
		1,
		"udp",
		0,
		net::ip::udp::endpoint(net::ip::address::from_string("127.0.0.1"), 1234)
	);
	std::cout << c.foundation() << '\n';
}

int main() {
	// get_local_candidate_test();
	candidate_test();
}