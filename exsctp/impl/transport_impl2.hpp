#pragma once

#include "net/dcsctp/public/dcsctp_socket.h"
#include "net/dcsctp/public/dcsctp_socket_factory.h"

#include <boost/intrusive/set.hpp>

#include <cassert>
#include <memory>
#include <chrono>
#include <random>

#include "config.hpp"
#include "utils/async_mutex.hpp"
#include "utils/async_queue.hpp"
#include "utils/shared_promise.hpp"
#include "utils/detached_with_data.hpp"
#include "utils/stop_when.hpp"
#include "utils/scope_guard.hpp"
#include "packet_queue.hpp"

namespace exsctp::impl {

template <class Interface>
struct transport_impl final: std::enable_shared_from_this<transport_impl<Interface>>,
                        dcsctp::DcSctpSocketCallbacks {
    transport_impl(
        std::shared_ptr<Interface> interface,
        const dcsctp::DcSctpOptions& options
    ):
        _interface{std::move(interface)},
        _send_q(options.max_send_buffer_size)
    {
        _dcsctp = dcsctp::DcSctpSocketFactory::Create("exsctp", *this, nullptr, options);
        if (!_interface || !_dcsctp)
            throw std::runtime_error("!_interface || !_dcsctp");
    }

    transport_impl(const transport_impl &) = delete;
    transport_impl &operator=(const transport_impl &) = delete;
    transport_impl(transport_impl &&) = delete;
    transport_impl &operator=(transport_impl &&) = delete;

    void start() {
        utils::detached_with_data(
            stdexec::starts_on(
                this->_interface->scheduler(),
                this->timeout_handler()
            ),
            this->shared_from_this()
        );
        utils::detached_with_data(
            stdexec::starts_on(
                this->_interface->scheduler(),
                this->packet_sender()
            ),
            this->shared_from_this()
        );
    }

    void stop() noexcept {
        if (!_is_open)
            return;
        _is_open = false;
        _notify_timeout_set_changed.set_value();
        _dcsctp.reset();
        assert(_timeout_set.empty());

        _notify_sender.set_value();
    }

    void dispatch_packet(std::span<const uint8_t> data) {
        _dcsctp->ReceivePacket(data);
    }

    auto Send(dcsctp::DcSctpMessage message, const dcsctp::SendOptions& send_options) {
        
    }
private:
    struct timeout_impl final:
        dcsctp::Timeout,
        boost::intrusive::set_base_hook<
            boost::intrusive::link_mode<boost::intrusive::auto_unlink>
        >
    {
        timeout_impl(transport_impl& t) noexcept:
            _impl{&t}
        {}

        timeout_impl(const timeout_impl&) = delete;
        timeout_impl(timeout_impl&&) = delete;
        timeout_impl& operator=(const timeout_impl&) = delete;
        timeout_impl& operator=(timeout_impl&&) = delete;

        // Called to start time timeout, with the duration in milliseconds as
        // `duration` and with the timeout identifier as `timeout_id`, which - if
        // the timeout expires - shall be provided to `DcSctpSocket::HandleTimeout`.
        //
        // `Start` and `Stop` will always be called in pairs. In other words will
        // ´Start` never be called twice, without a call to `Stop` in between.
        void Start(dcsctp::DurationMs duration, dcsctp::TimeoutID timeout_id) override;

        // Called to stop the running timeout.
        //
        // `Start` and `Stop` will always be called in pairs. In other words will
        // ´Start` never be called twice, without a call to `Stop` in between.
        //
        // `Stop` will always be called prior to releasing this object.
        void Stop() override;

        dcsctp::TimeoutID id() const noexcept {
            return _id;
        }

        auto expiry() const noexcept {
            return _expire_time;
        }

        struct key {
            using type = std::chrono::steady_clock::time_point;
            const type &operator()(const timeout_impl &t) const noexcept {
                return t._expire_time;
            }
        };
    private:
        dcsctp::TimeoutID _id{};
        std::chrono::steady_clock::time_point _expire_time{}; 
        transport_impl *_impl;
    };

    using timeout_set_type = boost::intrusive::set<
        timeout_impl,
        boost::intrusive::key_of_value<typename timeout_impl::key>,
        boost::intrusive::constant_time_size<false>
    >;

    exsctp::task<void> timeout_handler();
    exsctp::task<void> packet_sender();

    bool _is_open{true};
    std::shared_ptr<Interface> _interface;

    timeout_set_type _timeout_set{};
    exsctp::shared_promise<void> _notify_timeout_set_changed{};

    exsctp::packet_queue _send_q;
    exsctp::shared_promise<void> _notify_sender{};
    exsctp::shared_promise<void> _notify_user{};

    exsctp::shared_promise<void> _notify_reader{};

    std::unique_ptr<dcsctp::DcSctpSocketInterface> _dcsctp{};

private:
    // Called when the library wants the packet serialized as `data` to be sent.
    //
    // TODO(bugs.webrtc.org/12943): This method is deprecated, see
    // `SendPacketWithStatus`.
    //
    // Note that it's NOT ALLOWED to call into this library from within this
    // callback.
    void SendPacket(std::span<const uint8_t> /* data */) override;

    // Called when the library wants the packet serialized as `data` to be sent.
    //
    // Note that it's NOT ALLOWED to call into this library from within this
    // callback.
    dcsctp::SendPacketStatus
    SendPacketWithStatus(std::span<const uint8_t> data) override;

    // TODO(hbos): When dependencies have migrated to the other signature,
    // delete this version.
    std::unique_ptr<dcsctp::Timeout> CreateTimeout() override;

    // Returns the current time in milliseconds (from any epoch).
    //
    // TODO(bugs.webrtc.org/15593): This method is deprecated, see `Now`.
    //
    // Note that it's NOT ALLOWED to call into this library from within this
    // callback.
    dcsctp::TimeMs TimeMillis() override { return dcsctp::TimeMs(std::chrono::steady_clock::now().time_since_epoch() / std::chrono::milliseconds(1)); }

    // Called when the library needs a random number uniformly distributed
    // between `low` (inclusive) and `high` (exclusive). The random numbers used
    // by the library are not used for cryptographic purposes. There are no
    // requirements that the random number generator must be secure.
    //
    // Note that it's NOT ALLOWED to call into this library from within this
    // callback.
    uint32_t GetRandomInt(uint32_t low, uint32_t high) override;

    // Called when the library has received an SCTP message in full and delivers
    // it to the upper layer, given that
    // `DcSctpOptions::enable_receive_pull_mode` isn't enabled.
    //
    // It is allowed to call into this library from within this callback.
    void OnMessageReceived(dcsctp::DcSctpMessage message) override {}

    // Called when `DcSctpOptions::enable_receive_pull_mode` is enabled and the
    // library has one or more SCTP messages ready to be received with
    // `DcSctpSocket::GetNextMessage()`.
    //
    // It is allowed to call into this library from within this callback.
    void OnMessageReady() override;

    // Triggered when an non-fatal error is reported by either this library or
    // from the other peer (by sending an ERROR command). These should be
    // logged, but no other action need to be taken as the association is still
    // viable.
    //
    // It is allowed to call into this library from within this callback.
    void OnError(dcsctp::ErrorKind error, std::string_view message) override {}

    // Triggered when the socket has aborted - either as decided by this socket
    // due to e.g. too many retransmission attempts, or by the peer when
    // receiving an ABORT command. No other callbacks will be done after this
    // callback, unless reconnecting.
    //
    // It is allowed to call into this library from within this callback.
    void OnAborted(dcsctp::ErrorKind error, std::string_view message) override {}

    // Called when calling `Connect` succeeds, but also for incoming successful
    // connection attempts.
    //
    // It is allowed to call into this library from within this callback.
    void OnConnected() override {}

    // Called when the socket is closed in a controlled way. No other
    // callbacks will be done after this callback, unless reconnecting.
    //
    // It is allowed to call into this library from within this callback.
    void OnClosed() override {}

    // On connection restarted (by peer). This is just a notification, and the
    // association is expected to work fine after this call, but there could
    // have been packet loss as a result of restarting the association.
    //
    // It is allowed to call into this library from within this callback.
    void OnConnectionRestarted() override {}

    // Indicates that a stream reset request has failed.
    //
    // It is allowed to call into this library from within this callback.
    void
    OnStreamsResetFailed(std::span<const dcsctp::StreamID> outgoing_streams,
                         std::string_view reason) override {}

    // Indicates that a stream reset request has been performed.
    //
    // It is allowed to call into this library from within this callback.
    void
    OnStreamsResetPerformed(std::span<const dcsctp::StreamID> outgoing_streams) override {}

    // When a peer has reset some of its outgoing streams, this will be called.
    // An empty list indicates that all streams have been reset.
    //
    // It is allowed to call into this library from within this callback.
    void
    OnIncomingStreamsReset(std::span<const dcsctp::StreamID> incoming_streams) override {}
};

} // namespace exsctp::impl

#include "impl/transport_impl2.ipp"