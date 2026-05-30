#pragma once

#include "asioice/config.hpp"
#include "asioice/impl/agent_base.hpp"
#include "asioice/turn_client.hpp"
#include "asioice/detail/switch_case.hpp"
#include "asioice/socket_transport.hpp"

namespace asioice::impl {

template <class Sock> struct basic_agent_impl final : agent_base {
    using socket_type = Sock;
    using executor_type = typename socket_type::executor_type;
    using scheduler_type = asio2exec::basic_scheduler<executor_type>;
    using raw_transport = asioice::datagram_transport<socket_type>;
    using raw_transport_ptr = std::shared_ptr<raw_transport>;
    using turn_client_type = asioice::turn::client<raw_transport, true>;
    using timer_type = net::steady_timer::rebind_executor<executor_type>::other;

    basic_agent_impl(executor_type ex, agent_config config)
        : agent_base(ex, std::move(config)), _executor(std::move(ex)) {}

    executor_type get_executor() const noexcept { return _executor; }

    auto sendto(net::const_buffer data, uint8_t component) {
        auto p = this->find_nominated_pair(component);
        if (!p) {
            throw std::runtime_error(
                "No nominated candidate pair for component " +
                std::to_string(component));
        }
        return stdexec::just(std::move(p)) |
               stdexec::let_value([data](auto &pair) {
                   return utils::switch_case<
                              candidate_type::host, candidate_type::srflx,
                              candidate_type::prflx, candidate_type::relay>(
                              pair->local_candidate().type,
                              [data, &pair] {
                                  auto *sock =
                                      pair->local_candidate()
                                          .transport
                                          .template get<raw_transport>();
                                  assert(sock);
                                  return sock->async_send_to(
                                             data, pair->remote_candidate()
                                                       .endpoint) |
                                         __transform_sndr();
                              },
                              [data, &pair] {
                                  auto *sock =
                                      pair->local_candidate()
                                          .transport
                                          .template get<raw_transport>();
                                  assert(sock);
                                  return sock->async_send_to(
                                             data, pair->remote_candidate()
                                                       .endpoint) |
                                         __transform_sndr();
                              },
                              [data, &pair] {
                                  // TODO: Get the actual transport for prflx
                                  // candidate
                                  return pair->send(data);
                              },
                              [data, &pair] {
                                  auto *turn_client =
                                      pair->local_candidate()
                                          .transport
                                          .template get<turn_client_type>();
                                  assert(turn_client);
                                  return turn_client->async_send_to(
                                      data, pair->remote_candidate().endpoint);
                              }) |
                          stdexec::then(
                              [&pair](std::tuple<std::error_code, std::size_t>
                                          res) {
                                  if (!std::get<0>(res))
                                      pair->update_keepalive_time();
                                  return std::move(res);
                              });
               });
    }

  private:
    any_transport
    base_create_socket_transport(const net::ip::address &local_addr) override {
        socket_type sock(this->_executor);
#if ASIOICE_USE_BOOST_ASIO
        boost::system::error_code ec;
#else
        std::error_code ec;
#endif
        if (local_addr.is_v4()) {
            sock.open(net::ip::udp::v4(), ec);
        } else {
            sock.open(net::ip::udp::v6(), ec);
        }
        if (ec) {
            ICE_IN_DEBUG {
                std::cerr << "Failed to open socket: " << ec.message() << '\n';
            }
            return {};
        }

        // TODO: support port ranges
        sock.bind(asioice::endpoint(local_addr, 0), ec);
        if (ec) {
            ICE_IN_DEBUG {
                std::cerr << "Failed to bind address \""
                          << local_addr.to_string() << "\": " << ec.message()
                          << '\n';
            }
            return {};
        }

        auto transport = std::make_shared<raw_transport>(std::move(sock));

        ICE_IN_DEBUG {
            std::cout << "Host transport bound to "
                      << transport->local_endpoint().address() << ':'
                      << transport->local_endpoint().port() << '\n';
        }
        return transport;
    }

    std::shared_ptr<turn::turn_interface> base_create_turn_client(
        any_transport &sock, const asioice::endpoint &server,
        std::string_view username, std::string_view password) override {
        assert(sock);
        auto transport = sock.get_shared<raw_transport>();
        return std::make_shared<turn_client_type>(std::move(transport), server,
                                                  std::string(username),
                                                  std::string(password));
    }

    any_transport base_create_turn_transport(
        std::shared_ptr<turn::turn_interface> turn_interface) override {
        assert(turn_interface);
        auto turn_client =
            static_pointer_cast<turn_client_type>(std::move(turn_interface));
        return any_transport{std::move(turn_client)};
    }

    struct to_std_error_code {
        template <class... Args>
        static constexpr auto operator()(auto ec, Args &&...args) noexcept
            -> std::tuple<std::error_code, std::decay_t<Args>...> {
            return {std::error_code{ec}, std::forward<Args>(args)...};
        }
        template <class ErrorCode, class... Args>
        static constexpr auto
        operator()(std::tuple<ErrorCode, Args...> tup) noexcept
            -> std::tuple<std::error_code, Args...> {
            return std::apply(to_std_error_code{}, std::move(tup));
        }
    };

    static constexpr auto __transform_sndr() noexcept {
        return stdexec::then([](auto... result) noexcept {
            return to_std_error_code{}(result...);
        });
    }

    executor_type _executor;
};

} // namespace asioice::impl