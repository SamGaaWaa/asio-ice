#include "fixed_buffer.hpp"

#if ASIOICE_USE_BOOST > 0
#include <boost/asio/io_context.hpp>
namespace ice {
namespace net = boost::asio;
} // namespace ice
#else
#include <asio/io_context.hpp>
namespace ice {
namespace net = asio;
} // namespace ice
#endif

#include <iostream>

using namespace ice;

int main() {
    net::io_context ctx;
    fixed_buffer_pool pool(ctx, 16, 4096);

    for (int i = 0; i < 100; ++i) {
        fixed_buffer buf = pool.get();
        fixed_buffer buf1(std::move(buf));
        buf = std::move(buf1);
        std::cout << "buf size: " << buf.size() << "\n";
        if (buf.registered()) {
            std::cout << "buf is registered\n";
        } else {
            std::cout << "buf is not registered\n";
        }
    }
}