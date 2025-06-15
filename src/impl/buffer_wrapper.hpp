#pragma once

#include "config.hpp"

#if ASIOICE_USE_BOOST > 0
#include <boost/asio/buffers_iterator.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/buffers_iterator.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include <boost/container/small_vector.hpp>

namespace ice {

template <std::size_t N = 128> struct buffer_wrapper {
    template <class BufferSequence>
    buffer_wrapper(const BufferSequence &buffers) {
        auto buffer_first = net::buffer_sequence_begin(buffers);
        auto buffer_last = net::buffer_sequence_end(buffers);
        std::size_t buffer_count = std::distance(buffer_first, buffer_last);

        _buffers.resize(buffer_count);
        std::transform(
            buffer_first, buffer_last, _buffers.begin(),
            [](const auto &b) noexcept { return net::const_buffer(b); });
    }

    buffer_wrapper(const buffer_wrapper &other) = default;
    buffer_wrapper(buffer_wrapper &&other) = default;

    const auto &buffers() const noexcept { return _buffers; }
    auto &buffers() noexcept { return _buffers; }

  private:
    boost::container::small_vector<net::const_buffer, N> _buffers;
};

} // namespace ice