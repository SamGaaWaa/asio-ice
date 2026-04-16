#pragma once

#include "io_buffer2.hpp"

#include <openssl/bio.h>

#include <vector>
#include <deque>
#include <memory>

namespace asioice::ssl::impl {

struct datagram_bio {
    datagram_bio() noexcept = default;
    datagram_bio(const datagram_bio &) = delete;
    datagram_bio(datagram_bio &&) = delete;
    datagram_bio &operator=(const datagram_bio &) = delete;
    datagram_bio &operator=(datagram_bio &&) = delete;

    ::BIO *new_bio();

    void last_io_failed(bool failed) noexcept { _last_io_failed = failed; }

    bool last_io_failed() const noexcept { return _last_io_failed; }

    std::vector<uint8_t> out{};
    asioice::io_buffer_ptr in{};

  private:
    bool _last_io_failed{false};
};

} // namespace asioice::ssl::impl