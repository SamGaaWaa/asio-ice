namespace exsctp::impl {

template <class Interface>
void transport_impl<Interface>::timeout_impl::Start(
    dcsctp::DurationMs duration, dcsctp::TimeoutID timeout_id) {
    this->_id = timeout_id;
    this->_expire_time =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(*duration);
    this->_impl->_timeout_set.insert(*this);
    if (&*this->_impl->_timeout_set.begin() == this) {
        this->_impl->_notify_timeout_set_changed.set_value();
    }
}

template <class Interface>
void transport_impl<Interface>::timeout_impl::Stop() {
    bool should_notify = false;
    if (!this->_impl->_timeout_set.empty() &&
        &*this->_impl->_timeout_set.begin() == this) {
        should_notify = true;
    }
    if (this->is_linked())
        this->unlink();
    if (should_notify)
        this->_impl->_notify_timeout_set_changed.set_value();
}

template <class Interface>
exsctp::task<void> transport_impl<Interface>::timeout_handler() {
    while (this->_running) {
        auto now = std::chrono::steady_clock::now();
        if (this->_timeout_set.empty())
            goto LONG_SLEEP;
        while (!this->_timeout_set.empty() &&
               this->_timeout_set.begin()->expiry() <= now) {
            auto &timeout = *this->_timeout_set.begin();
            timeout.unlink();
            this->_dcsctp->HandleTimeout(timeout.id());
            now = std::chrono::steady_clock::now();
        }
        if (this->_timeout_set.empty())
            goto LONG_SLEEP;
        if (!this->_running)
            break;
        co_await utils::stop_when(
            this->_interface->schedule_at(this->_timeout_set.begin()->expiry()),
            this->_notify_timeout_set_changed.get_future());
        continue;
    LONG_SLEEP:
        if (!this->_running)
            break;
        co_await utils::stop_when(
            this->_interface->schedule_after(std::chrono::seconds(3600)),
            this->_notify_timeout_set_changed.get_future());
    }
}

template <class Interface>
exsctp::task<void> transport_impl<Interface>::packet_sender() {
    while (this->_running) {
        if (this->_send_q.empty()) {
            co_await (this->_notify_sender.get_future() |
                      stdexec::continues_on(this->_interface->scheduler()));
            continue;
        }
        bool buffered_high = this->send_queue_buffered_high();
        auto packet = this->_send_q.peek();
        auto [ec, n] = co_await this->_interface->send(packet);
        if (ec) {
            SAMLOG_WARN(auto sink) {
                sink("packet_sender error: {}\n", ec.message());
            };
            co_return;
        }
        if (n == 0) {
            SAMLOG_WARN(auto sink) { sink("packet_sender sent 0 bytes\n"); };
            co_return;
        }
        if (n < packet.size()) {
            SAMLOG_WARN(auto sink) {
                sink("packet_sender sent partial packet: {} of {} bytes\n", n,
                     packet.size());
            };
        }
        this->_send_q.pop();
        if (buffered_high && !this->send_queue_buffered_high())
            this->_notify_send_queue_buffered_low.set_value();
    }
}

template <class Interface>
void transport_impl<Interface>::SendPacket(std::span<const uint8_t> data) {
    bool should_notify = this->_send_q.empty();
    if (this->_send_q.write(data) && should_notify)
        this->_notify_sender.set_value();
}

template <class Interface>
dcsctp::SendPacketStatus
transport_impl<Interface>::SendPacketWithStatus(std::span<const uint8_t> data) {
    bool should_notify = this->_send_q.empty();
    if (this->_send_q.write(data)) [[likely]] {
        if (should_notify)
            this->_notify_sender.set_value();
        return dcsctp::SendPacketStatus::kSuccess;
    }
    return dcsctp::SendPacketStatus::kTemporaryFailure;
}

template <class Interface>
std::unique_ptr<dcsctp::Timeout> transport_impl<Interface>::CreateTimeout() {
    return std::make_unique<transport_impl<Interface>::timeout_impl>(*this);
}

template <class Interface>
uint32_t transport_impl<Interface>::GetRandomInt(uint32_t low, uint32_t high) {
    static thread_local std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<uint32_t> distribution(low, high);
    return distribution(generator);
}

template <class Interface>
exsctp::inline_task<bool>
transport_impl<Interface>::send(exsctp::message msg,
                                dcsctp::SendOptions send_options) {
    if (this->closed())
        co_return false;
    auto lk = co_await this->_send_mtx.lock();
    while (this->send_queue_buffered_high()) {
        if (this->closed())
            co_return false;
        co_await (
            utils::stop_when(this->_notify_send_queue_buffered_low.get_future(),
                             this->_on_state_changed.get_future()) |
            stdexec::continues_on(this->_interface->scheduler()));
    }
    while (!this->closed()) {
        dcsctp::DcSctpMessage sctp_msg(
            dcsctp::StreamID(msg.stream_id), dcsctp::PPID(msg.ppid),
            std::vector<uint8_t>(msg.data.begin(), msg.data.end()));
        auto ret = this->_dcsctp->Send(std::move(sctp_msg), send_options);
        if (ret == dcsctp::SendStatus::kErrorResourceExhaustion) [[unlikely]] {
            co_await (utils::stop_when(
                          this->_notify_total_buffered_amount_low.get_future(),
                          this->_on_state_changed.get_future()) |
                      stdexec::continues_on(this->_interface->scheduler()));
            continue;
        }
        co_return ret == dcsctp::SendStatus::kSuccess;
    }
    co_return false;
}

template <class Interface> auto transport_impl<Interface>::read() noexcept {
    auto work =
        stdexec::just(std::optional<dcsctp::DcSctpMessage>{}) |
        stdexec::let_value([this](auto &res) {
            return stdexec::just() | stdexec::then([this, &res] {
                       res = this->_dcsctp->GetNextMessage();
                       return res.has_value();
                   }) |
                   stdexec::let_value([this](bool has_msg) {
                       return utils::if_else(
                           stdexec::just(has_msg || this->closed()),
                           [] { return stdexec::just(true); },
                           [this] {
                               return exec::when_any(
                                          this->_notify_reader.get_future(),
                                          this->_on_state_changed
                                              .get_future()) |
                                      stdexec::continues_on(
                                          this->_interface->scheduler()) |
                                      stdexec::then([] { return false; });
                           });
                   }) |
                   exec::repeat_until() |
                   stdexec::then([&res] { return std::move(res); });
        });
    return this->_read_mtx.lock() |
           stdexec::let_value([work = std::move(work)](auto &lk) mutable {
               return std::move(work);
           });
}

template <class Interface> auto transport_impl<Interface>::connect() noexcept {
    if (!this->connected())
        this->_dcsctp->Connect();
    return utils::if_else(
        stdexec::just(this->connected()), [] { return stdexec::just(true); },
        [this] {
            return this->_on_state_changed.get_future() |
                   stdexec::continues_on(this->_interface->scheduler()) |
                   stdexec::then([this] { return this->connected(); });
        });
}

template <class Interface> auto transport_impl<Interface>::accept() noexcept {
    return utils::if_else(
        stdexec::just(this->connected()), [] { return stdexec::just(true); },
        [this] {
            return this->_on_state_changed.get_future() |
                   stdexec::continues_on(this->_interface->scheduler()) |
                   stdexec::then([this] { return this->connected(); });
        });
}

template <class Interface> auto transport_impl<Interface>::shutdown() noexcept {
    if (this->_dcsctp->state() != dcsctp::SocketState::kShuttingDown &&
        this->_dcsctp->state() != dcsctp::SocketState::kClosed)
        this->_dcsctp->Shutdown();
    return utils::if_else(
        stdexec::just(this->closed()), [] { return stdexec::just(true); },
        [this] {
            return this->_on_state_changed.get_future() |
                   stdexec::continues_on(this->_interface->scheduler()) |
                   stdexec::then([this] { return this->closed(); });
        });
}

} // namespace exsctp::impl