#pragma once

#include "exsctp/interface.hpp"
#include "exsctp/impl/transport_impl.hpp"
#include "exsctp/option.hpp"

#include <memory>

namespace exsctp {

template <IOInterface Interface = any_io_interface> class basic_transport {
    static dcsctp::DcSctpOptions
    to_dcsctp_options(const exsctp::sctp_options &opt) noexcept {
        dcsctp::DcSctpOptions res{};

        res.local_port = opt.local_port;
        res.remote_port = opt.remote_port;
        res.announced_maximum_incoming_streams =
            opt.announced_maximum_incoming_streams;
        res.announced_maximum_outgoing_streams =
            opt.announced_maximum_outgoing_streams;
        res.mtu = opt.mtu;
        res.max_message_size = opt.max_message_size;
        res.default_stream_priority =
            dcsctp::StreamPriority(opt.default_stream_priority);
        res.max_receiver_window_buffer_size =
            opt.max_receiver_window_buffer_size;
        res.enable_receive_pull_mode = true;
        res.max_send_buffer_size = opt.max_send_buffer_size;
        res.per_stream_send_queue_limit = opt.per_stream_send_queue_limit;
        res.total_buffered_amount_low_threshold =
            opt.total_buffered_amount_low_threshold;
        res.rtt_max = dcsctp::DurationMs(opt.rtt_max.count());
        res.rto_initial = dcsctp::DurationMs(opt.rto_initial.count());
        res.rto_max = dcsctp::DurationMs(opt.rto_max.count());
        res.rto_min = dcsctp::DurationMs(opt.rto_min.count());
        res.t1_init_timeout = dcsctp::DurationMs(opt.t1_init_timeout.count());
        res.t1_cookie_timeout =
            dcsctp::DurationMs(opt.t1_cookie_timeout.count());
        res.t2_shutdown_timeout =
            dcsctp::DurationMs(opt.t2_shutdown_timeout.count());
        if (opt.max_timer_backoff_duration)
            res.max_timer_backoff_duration =
                dcsctp::DurationMs(opt.max_timer_backoff_duration->count());
        res.heartbeat_interval =
            dcsctp::DurationMs(opt.heartbeat_interval.count());
        res.delayed_ack_max_timeout =
            dcsctp::DurationMs(opt.delayed_ack_max_timeout.count());
        res.min_rtt_variance = dcsctp::DurationMs(opt.min_rtt_variance.count());
        res.cwnd_mtus_initial = opt.cwnd_mtus_initial;
        res.cwnd_mtus_min = opt.cwnd_mtus_min;
        res.avoid_fragmentation_cwnd_mtus = opt.avoid_fragmentation_cwnd_mtus;
        res.immediate_sack_under_cwnd_mtus = opt.immediate_sack_under_cwnd_mtus;
        res.max_burst = opt.max_burst;
        res.max_retransmissions = opt.max_retransmissions;
        res.max_init_retransmits = opt.max_init_retransmits;
        res.enable_partial_reliability = opt.enable_partial_reliability;
        res.enable_message_interleaving = opt.enable_message_interleaving;
        res.heartbeat_interval_include_rtt = opt.heartbeat_interval_include_rtt;
        res.disable_checksum_verification = opt.disable_checksum_verification;
        res.zero_checksum_alternate_error_detection_method =
            opt.zero_checksum_alternate_error_detection_method;

        return res;
    }

    static dcsctp::SendOptions
    to_dcsctp_options(const exsctp::send_options &opt) noexcept {
        dcsctp::SendOptions res{};

        res.unordered = dcsctp::IsUnordered(opt.unordered);
        if (opt.lifetime)
            res.lifetime = dcsctp::DurationMs(opt.lifetime->count());
        res.max_retransmissions = opt.max_retransmissions;

        return res;
    }

  public:
    using interface_type = Interface;
    using impl_type = impl::transport_impl<Interface>;

    basic_transport(std::shared_ptr<interface_type> interface,
                    const exsctp::sctp_options &options)
        : _impl(std::make_shared<impl_type>(std::move(interface),
                                            to_dcsctp_options(options))) {}

    basic_transport(const basic_transport &) = delete;
    basic_transport &operator=(const basic_transport &) = delete;

    basic_transport(basic_transport &&other) noexcept
        : _impl(std::move(other._impl)) {}

    basic_transport &operator=(basic_transport &&other) noexcept {
        if (&other != this) {
            stop();
            _impl = std::exchange(other._impl, nullptr);
        }
        return *this;
    }

    ~basic_transport() { stop(); }

    void swap(basic_transport &other) noexcept {
        std::exchange(_impl, other._impl);
    }

    void start() { _impl->start(); }

    void stop() noexcept {
        if (_impl) {
            _impl->stop();
            _impl = nullptr;
        }
    }

    auto &interface() noexcept { return _impl->interface(); }

    const auto &interface() const noexcept { return _impl->interface(); }

    const dcsctp::DcSctpSocketInterface &socket() const noexcept {
        return _impl->socket();
    }

    dcsctp::DcSctpSocketInterface &socket() noexcept { return _impl->socket(); }

    void dispatch_packet(std::span<const uint8_t> data) {
        _impl->dispatch_packet(data);
    }

    auto send(const exsctp::message &msg,
              const exsctp::send_options &send_options) {
        return _impl->send(msg, to_dcsctp_options(send_options));
    }

    auto read() noexcept { return _impl->read(); }

    bool connected() const noexcept { return _impl->connected(); }
    auto connect() noexcept { return _impl->connect(); }

    auto accept() noexcept { return _impl->accept(); }

    bool closed() const noexcept { return _impl->closed(); }

    // Gracefully shutdowns the socket and sends all outstanding data.
    auto shutdown() noexcept { return _impl->shutdown(); }

    // Closes the connection non-gracefully. Will send ABORT if the connection
    // is not already closed.
    void close() noexcept { _impl->close(); }

    void on_outgoing_reseted(
        boost::compat::move_only_function<
            void(std::span<const dcsctp::StreamID>, bool, std::string_view)>
            cb) {
        _impl->on_outgoing_reseted(std::move(cb));
    }

    void on_incoming_reseted(boost::compat::move_only_function<
                             void(std::span<const dcsctp::StreamID>)>
                                 cb) {
        _impl->on_incoming_reseted(std::move(cb));
    }

    void on_buffered_amount_low(
        boost::compat::move_only_function<void(dcsctp::StreamID)> cb) {
        _impl->on_buffered_amount_low(std::move(cb));
    }

  private:
    std::shared_ptr<impl_type> _impl;
};

using transport = basic_transport<>;

} // namespace exsctp