#pragma once

#include "asioice/detail/io_buffer.hpp"
#include "asioice/detail/packet_queue.hpp"
#include "asioice/detail/shared_promise.hpp"

#include <openssl/bio.h>

#include <vector>
#include <deque>
#include <memory>

namespace asioice::ssl::impl {

struct datagram_bio {
    struct recv_queue {
        recv_queue(std::size_t max_bytes) noexcept : _max_bytes{max_bytes} {}

        recv_queue(const recv_queue &) = delete;
        recv_queue(recv_queue &&) = delete;
        recv_queue &operator=(const recv_queue &) = delete;
        recv_queue &operator=(recv_queue &&) = delete;

        ~recv_queue() { clear(); }

        bool empty() const noexcept { return _head == nullptr; }

        asioice::io_buffer &peek() noexcept { return *_head; }

        const asioice::io_buffer &peek() const noexcept { return *_head; }

        void push(asioice::io_buffer_ptr ptr) noexcept {
            if (!ptr || ptr->empty() || get_bytes(*ptr) + _bytes > _max_bytes)
                return;
            asioice::io_buffer *buf = ptr.release().release();
            buf->set_next(nullptr);

            bool should_notify = false;
            if (!_tail) {
                _head = buf;
                _tail = buf;
                should_notify = true;
            } else {
                _tail->set_next(buf);
                _tail = buf;
            }
            _bytes += get_bytes(*buf);
            if (should_notify)
                _notify_reader.set_value();
        }

        void pop() noexcept {
            if (!_head)
                return;
            asioice::io_buffer *res = _head;
            _head = res->next();
            if (!_head)
                _tail = nullptr;
            res->set_next(nullptr);
            _bytes -= get_bytes(*res);
            asioice::io_buffer_ptr(std::unique_ptr<asioice::io_buffer>(res));
        }

        void clear() noexcept {
            while (!empty())
                pop();
        }

        auto wait() noexcept { return _notify_reader.get_future(); }

      private:
        static constexpr std::size_t
        get_bytes(const asioice::io_buffer &buf) noexcept {
            return buf.size() + sizeof(asioice::io_buffer);
        }

        asioice::io_buffer *_head{nullptr};
        asioice::io_buffer *_tail{nullptr};
        std::size_t _bytes{0};
        asioice::shared_promise<void> _notify_reader{};
        const std::size_t _max_bytes;
    };

    datagram_bio(std::size_t max_send_buf_size = 16 * 1024,
                 std::size_t max_recv_buf_size = 16 * 1024) noexcept
        : out{max_send_buf_size}, in{max_recv_buf_size} {}

    datagram_bio(const datagram_bio &) = delete;
    datagram_bio(datagram_bio &&) = delete;
    datagram_bio &operator=(const datagram_bio &) = delete;
    datagram_bio &operator=(datagram_bio &&) = delete;

    ::BIO *new_bio();

    void last_io_failed(bool failed) noexcept { _last_io_failed = failed; }

    bool last_io_failed() const noexcept { return _last_io_failed; }

    asioice::utils::packet_queue out;
    recv_queue in;

  private:
    bool _last_io_failed{false};
};

} // namespace asioice::ssl::impl