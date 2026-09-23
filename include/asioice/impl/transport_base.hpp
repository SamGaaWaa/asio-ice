#pragma once

#include "asioice/config.hpp"
#include "asioice/detail/buffer_wrapper.hpp"
#include "asioice/detail/if_else.hpp"
#include "asioice/address.hpp"
#include "asioice/impl/operation_queue.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/any_io_executor.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/any_io_executor.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include <stdexcept>
#include <system_error>
#include <memory>
#include <cassert>

#include <stdexec/execution.hpp>

namespace asioice {

struct transport_base {
    struct send_op_base
        : public boost::intrusive::list_base_hook<
              boost::intrusive::link_mode<boost::intrusive::safe_link>> {
        using operation_state_concept = stdexec::operation_state_tag;

        virtual void set_value(std::error_code ec, std::size_t n) noexcept = 0;
        virtual void set_error(std::exception_ptr) noexcept = 0;
        virtual void set_stopped() noexcept = 0;

        virtual bool stoppable() const noexcept { return true; }

        virtual stdexec::inplace_stop_token stop_token() const noexcept {
            return {};
        }

        virtual std::span<const net::const_buffer>
        get_buffers() const noexcept = 0;
        virtual const endpoint &get_endpoint() const noexcept = 0;
    };

    using send_op_queue = impl::op_queue<send_op_base>;

  protected:
    send_op_queue &operation_queue() noexcept { return _send_q; }

    const send_op_queue &operation_queue() const noexcept { return _send_q; }

  private:
    template <class R> struct sendto_op final : send_op_base {
        template <class R1>
        sendto_op(R1 &&r, buffer_wrapper &&buf, endpoint &&ep, send_op_queue &q)
            : _r{std::forward<R1>(r)},
              _token{stdexec::get_stop_token(stdexec::get_env(_r))},
              _buffers{std::move(buf)}, _ep{std::move(ep)}, _op_q{q} {}

        using stop_token_t = stdexec::stop_token_of_t<stdexec::env_of_t<R> &>;
        static constexpr bool is_inplace_stop_source =
            std::same_as<stop_token_t, stdexec::inplace_stop_token>;

        struct on_stop_t {
            sendto_op &self;
            void operator()() noexcept {
                if (self.is_linked()) {
                    self._op_q.queue().erase(
                        self._op_q.queue().iterator_to(self));
                    stdexec::set_stopped(std::move(self._r));
                    return;
                }
                // under processing
                if constexpr (!is_inplace_stop_source &&
                              !stdexec::unstoppable_token<stop_token_t>)
                    self._stop_source.request_stop();
            }
        };

        using stop_callback_t =
            typename stop_token_t::template callback_type<on_stop_t>;

        void set_value(std::error_code ec, std::size_t n) noexcept override {
            assert(!this->is_linked());
            _stop_cb.reset();
            stdexec::set_value(std::move(_r), ec, n);
        }

        void set_error(std::exception_ptr e) noexcept override {
            assert(!this->is_linked());
            _stop_cb.reset();
            stdexec::set_error(std::move(_r), std::move(e));
        }

        void set_stopped() noexcept override {
            assert(!this->is_linked());
            _stop_cb.reset();
            stdexec::set_stopped(std::move(_r));
        }

        std::span<const net::const_buffer>
        get_buffers() const noexcept override {
            return _buffers.buffers();
        }

        const endpoint &get_endpoint() const noexcept override { return _ep; }

        bool stoppable() const noexcept override {
            return !stdexec::unstoppable_token<stop_token_t>;
        }

        stdexec::inplace_stop_token stop_token() const noexcept override {
            if constexpr (stdexec::unstoppable_token<stop_token_t>)
                return {};
            else if constexpr (is_inplace_stop_source)
                return _token;
            else
                return _stop_source.stop_token();
        }

        void start() noexcept {
            const auto env = stdexec::get_env(_r);
            const auto token = stdexec::get_stop_token(env);
            if (token.stop_requested()) {
                stdexec::set_stopped(std::move(_r));
                return;
            }
            _stop_cb.emplace(token, on_stop_t{*this});
            _op_q.push_back(*this);
        }

        R _r;
        stop_token_t _token;
        buffer_wrapper _buffers;
        endpoint _ep;
        send_op_queue &_op_q;
        std::conditional_t<is_inplace_stop_source ||
                               stdexec::unstoppable_token<stop_token_t>,
                           std::monostate, stdexec::inplace_stop_source>
            _stop_source{};
        std::optional<stop_callback_t> _stop_cb{};
    };

    struct sendto_sender {
        using sender_concept = stdexec::sender_tag;
        using completion_signatures = stdexec::completion_signatures<
            stdexec::set_value_t(std::error_code ec, std::size_t n),
            stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>;

        template <class R> auto connect(R &&r) && {
            return sendto_op<std::decay_t<R>>{
                std::forward<R>(r), std::move(buffers), std::move(ep), *q};
        }

        buffer_wrapper buffers;
        endpoint ep;
        send_op_queue *q;
    };

  public:
    transport_base() = default;

    transport_base(const transport_base &) = delete;
    transport_base(transport_base &&) = delete;
    transport_base &operator=(const transport_base &) = delete;
    transport_base &operator=(transport_base &&) = delete;

    virtual ~transport_base() { assert(_send_q.empty()); }

    virtual void start() {}
    virtual void stop() noexcept {}

    template <class ConstBufferSequence>
    auto async_send_to(const ConstBufferSequence &buffers, endpoint ep) {
        return sendto_sender{{buffers}, ep, &_send_q};
    }

  private:
    send_op_queue _send_q{};
};

} // namespace asioice