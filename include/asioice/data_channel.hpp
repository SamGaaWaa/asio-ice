#pragma once

#include "asioice/impl/data_channel_impl.hpp"

namespace asioice {

using impl::data_channel_message;
using impl::data_channel_options;

template <class Sctp> struct data_channel_manager {
    using impl_type = impl::data_channel_manager_impl<Sctp>;
    using sctp_type = Sctp;
    using data_channel = typename impl_type::data_channel;
    using channel_callback = typename impl_type::channel_callback;

    data_channel_manager(std::shared_ptr<sctp_type> sctp, bool is_client)
        : _impl(std::make_shared<impl_type>(std::move(sctp), is_client)) {}

    data_channel_manager(const data_channel_manager &) = delete;
    data_channel_manager &operator=(const data_channel_manager &) = delete;

    data_channel_manager(data_channel_manager &&other) noexcept
        : _impl{std::move(other._impl)} {}

    data_channel_manager &operator=(data_channel_manager &&other) noexcept {
        if (this != &other) {
            stop();
            _impl = std::move(other._impl);
        }
        return *this;
    }

    ~data_channel_manager() { stop(); }

    void start() { _impl->start(); }

    void stop() noexcept {
        if (_impl) {
            _impl->on_remote_channel(nullptr);
            _impl->stop();
            _impl = nullptr;
        }
    }

    const auto &sctp() const noexcept { return _impl->sctp(); }
    auto &sctp() noexcept { return _impl->sctp(); }

    auto on_remote_channel(channel_callback cb) {
        _impl->on_remote_channel(std::move(cb));
    }

    auto
    create_data_channel(std::string label,
                        data_channel_options options = data_channel_options{}) {
        return _impl->create_data_channel(std::move(label), std::move(options));
    }

  private:
    std::shared_ptr<impl_type> _impl;
};

} // namespace asioice
