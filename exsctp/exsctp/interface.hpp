#pragma once

#include "exsctp/task.hpp"

#include <exec/any_sender_of.hpp>

#include <system_error>
#include <cstddef>
#include <cstdint>
#include <span>
#include <concepts>
#include <chrono>

#include <boost/system.hpp>

namespace exsctp {

struct any_io_interface {
    using completions_t =
        stdexec::completion_signatures<stdexec::set_value_t()>;
    using any_sender_t = exec::any_sender<exec::any_receiver<completions_t>>;
    using fwd_progress_query_t = stdexec::forward_progress_guarantee(
        stdexec::get_forward_progress_guarantee_t) noexcept;
    using scheduler_type =
        exec::any_scheduler<any_sender_t, exec::queries<fwd_progress_query_t>>;

    void start() {}
    void stop() noexcept {}

    virtual exsctp::task<std::tuple<std::error_code, std::size_t>>
    send(std::span<const uint8_t> data) = 0;

    virtual exsctp::task<std::tuple<std::error_code, std::size_t>>
    send(std::span<std::span<const uint8_t>> data_array) {
        std::size_t total = 0;
        for (const auto &data : data_array) {
            auto [ec, n] = co_await send(data);
            total += n;
            if (ec)
                co_return std::make_tuple(ec, total);
        }
        co_return std::make_tuple(std::error_code{}, total);
    }

    virtual scheduler_type scheduler() const noexcept {
        return scheduler_type{stdexec::inline_scheduler{}};
    }

    virtual exsctp::task<void>
        schedule_at(std::chrono::steady_clock::time_point) = 0;
    virtual exsctp::task<void> schedule_after(std::chrono::milliseconds ms) = 0;
    virtual exsctp::task<void> schedule_after(std::chrono::seconds s) {
        return schedule_after(
            std::chrono::duration_cast<std::chrono::milliseconds>(s));
    }

    template <class Duration>
        requires(!std::same_as<Duration, std::chrono::milliseconds> &&
                 !std::same_as<Duration, std::chrono::seconds>)
    auto schedule_after(Duration d) {
        return schedule_after(
            std::chrono::duration_cast<std::chrono::milliseconds>(d));
    }

    virtual std::size_t mtu() const noexcept { return 1191; }
};

struct __send_receiver {
    using receiver_concept = stdexec::receiver_t;
    void set_value(std::tuple<std::error_code, std::size_t>) && noexcept {}
    void
    set_value(std::tuple<boost::system::error_code, std::size_t>) && noexcept {}
    void set_value(std::error_code, std::size_t) && noexcept {}
    void set_value(boost::system::error_code, std::size_t) && noexcept {}
    void set_error(std::exception_ptr) && noexcept {}
    void set_stopped() && noexcept {}
};

struct __timeout_receiver {
    using receiver_concept = stdexec::receiver_t;
    void set_value() && noexcept {}
    void set_error(std::exception_ptr) && noexcept {}
    void set_stopped() && noexcept {}
};

template <class T>
concept IOInterface = requires(
    T *interface, const T *const_interface, std::span<const uint8_t> data,
    std::span<std::span<const uint8_t>> data_array,
    std::chrono::steady_clock::time_point steady_time,
    std::chrono::milliseconds ms, std::chrono::seconds sec) {
    interface->start();
    {
        interface->stop()
    } noexcept;
    { interface->scheduler() } -> stdexec::scheduler;
    stdexec::connect(
        stdexec::starts_on(stdexec::inline_scheduler{}, interface->send(data)),
        __send_receiver{});
    stdexec::connect(stdexec::starts_on(stdexec::inline_scheduler{},
                                        interface->send(data_array)),
                     __send_receiver{});
    stdexec::connect(stdexec::starts_on(stdexec::inline_scheduler{},
                                        interface->schedule_at(steady_time)),
                     __timeout_receiver{});
    stdexec::connect(stdexec::starts_on(stdexec::inline_scheduler{},
                                        interface->schedule_after(ms)),
                     __timeout_receiver{});
    stdexec::connect(stdexec::starts_on(stdexec::inline_scheduler{},
                                        interface->schedule_after(sec)),
                     __timeout_receiver{});
    { const_interface->mtu() } -> std::same_as<std::size_t>;
};

static_assert(IOInterface<any_io_interface>);

} // namespace exsctp