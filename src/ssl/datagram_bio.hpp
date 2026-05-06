#pragma once

#include "io_buffer2.hpp"
#include "packet_queue.hpp"

#include <openssl/bio.h>

#include <vector>
#include <deque>
#include <memory>

namespace asioice::ssl::impl {

struct datagram_bio {
    datagram_bio(std::size_t max_send_buf_size = 16 * 1024) noexcept
        : out{max_send_buf_size} {}

    datagram_bio(const datagram_bio &) = delete;
    datagram_bio(datagram_bio &&) = delete;
    datagram_bio &operator=(const datagram_bio &) = delete;
    datagram_bio &operator=(datagram_bio &&) = delete;

    ::BIO *new_bio();

    void last_io_failed(bool failed) noexcept { _last_io_failed = failed; }

    bool last_io_failed() const noexcept { return _last_io_failed; }

    asioice::utils::packet_queue out{};
    asioice::io_buffer_ptr in{};

  private:
    bool _last_io_failed{false};
};

} // namespace asioice::ssl::impl