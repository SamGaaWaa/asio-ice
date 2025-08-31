#pragma once

#include "config.hpp"

#include <type_traits>

#if ASIOICE_USE_BOOST_ASIO > 0
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

#include <boost/container/static_vector.hpp>

namespace ice {

struct buffer_wrapper {
    // TODO: 
    static constexpr std::size_t  max_buffers_count = 64;
    using buffer_sequence_type = boost::container::static_vector<net::const_buffer, max_buffers_count>;

    template <class BufferSequence>
    buffer_wrapper(const BufferSequence &buffers) {
        auto buffer_first = net::buffer_sequence_begin(buffers);
        auto buffer_last = net::buffer_sequence_end(buffers);
        std::size_t buffer_count = std::distance(buffer_first, buffer_last);
        if (buffer_count > max_buffers_count)
            throw std::runtime_error("Too many buffers");

        _buffers.resize(buffer_count);
        std::transform(
            buffer_first, buffer_last, _buffers.begin(),
            [](const auto &b) noexcept { return net::const_buffer(b); });
    }

    buffer_wrapper(const buffer_wrapper &other) = default;
    buffer_wrapper(buffer_wrapper &&other) = default;

    const auto &buffers() const noexcept { return _buffers; }
    auto &buffers() noexcept { return _buffers; }

    auto begin() const noexcept { return _buffers.begin(); }
    auto end() const noexcept { return _buffers.end(); }
    auto data() const noexcept { return _buffers.data(); }

  private:
    buffer_sequence_type _buffers;
};

} // namespace ice