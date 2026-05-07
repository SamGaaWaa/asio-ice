namespace exsctp::impl {

template <class Interface>
void
transport_impl<Interface>::timeout_impl::Start(dcsctp::DurationMs duration, dcsctp::TimeoutID timeout_id)
{
    this->_id = timeout_id;
    this->_expire_time = std::chrono::steady_clock::now() + std::chrono::milliseconds(*duration);
    this->_impl->_timeout_set.insert(*this);
    if (&*this->_impl->_timeout_set.begin() == this) {
        this->_impl->_notify_timeout_set_changed.set_value();
    }
}

template <class Interface>
void
transport_impl<Interface>::timeout_impl::Stop()
{
    bool should_notify = false;
    if (!this->_impl->_timeout_set.empty() &&
        &*this->_impl->_timeout_set.begin() == this)
    {
        should_notify = true;
    }
    if (this->is_linked())
        this->unlink();
    if (should_notify)
        this->_impl->_notify_timeout_set_changed.set_value();
}

template <class Interface>
exsctp::task<void>
transport_impl<Interface>::timeout_handler()
{
    while (this->_is_open) {
        auto now = std::chrono::steady_clock::now();
        if (this->_timeout_set.empty())
            goto LONG_SLEEP;
        while (!this->_timeout_set.empty() &&
                this->_timeout_set.begin()->expiry() <= now)
        {
            auto& timeout = *this->_timeout_set.begin();
            timeout.unlink();
            this->_dcsctp->HandleTimeout(timeout.id());
            now = std::chrono::steady_clock::now();
        }
        if (this->_timeout_set.empty())
            goto LONG_SLEEP;
        if (!this->_is_open)
            break;
        co_await utils::stop_when(
            this->_interface->schedule_at(this->_timeout_set.begin()->expiry()),
            this->_notify_timeout_set_changed.get_future()
        );
        continue;
    LONG_SLEEP:
        if (!this->_is_open)
            break;
        co_await utils::stop_when(
            this->_interface->schedule_after(std::chrono::seconds(3600)),
            this->_notify_timeout_set_changed.get_future()
        );
    }
}

template <class Interface>
void
transport_impl<Interface>::SendPacket(std::span<const uint8_t> data)
{
    this->_send_q.write(data);
}

template <class Interface>
dcsctp::SendPacketStatus
transport_impl<Interface>::SendPacketWithStatus(std::span<const uint8_t> data)
{
    if (this->_send_q.write(data)) [[likely]]
        return dcsctp::SendPacketStatus::kSuccess;
    return dcsctp::SendPacketStatus::kTemporaryFailure;
}

template <class Interface>
std::unique_ptr<dcsctp::Timeout>
transport_impl<Interface>::CreateTimeout() {
    return std::make_unique<transport_impl<Interface>::timeout_impl>(*this);
}

template <class Interface>
uint32_t
transport_impl<Interface>::GetRandomInt(uint32_t low, uint32_t high)
{
    static thread_local std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<uint32_t> distribution(low, high);
    return distribution(generator);
}

template <class Interface>
void
transport_impl<Interface>::OnMessageReady() {
    // TODO
    this->_notify_reader.set_one_value();
}

} // namespace exsctp::impl