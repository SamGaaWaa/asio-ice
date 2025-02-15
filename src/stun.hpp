#pragma once

#include "config.hpp"
#include "endian.hpp"

#if ASIOICE_USE_BOOST > 0
#include <boost/asio/ip/address.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/ip/address.hpp>
namespace ice {
namespace net = asio;
}
#endif
#include <boost/container/small_vector.hpp>
#include <boost/container/static_vector.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace ice::stun {

struct class_t {
  static constexpr uint16_t STUN_CLASS_REQUEST = 0x0000;
  static constexpr uint16_t STUN_CLASS_INDICATION = 0x0010;
  static constexpr uint16_t STUN_CLASS_RESP_SUCCESS = 0x0100;
  static constexpr uint16_t STUN_CLASS_RESP_ERROR = 0x0110;

  constexpr class_t() : _val(0) {}
  constexpr class_t(uint16_t val) : _val(val) {}

  constexpr operator uint16_t() const { return _val; }
  constexpr operator uint16_t &() { return _val; }

private:
  uint16_t _val;
};

struct method_t {
  static constexpr uint16_t STUN_METHOD_BINDING = 0x0001;

  // Methods for TURN
  // See https://www.rfc-editor.org/rfc/rfc8656.html#section-17
  static constexpr uint16_t STUN_METHOD_ALLOCATE = 0x003;
  static constexpr uint16_t STUN_METHOD_REFRESH = 0x004;
  static constexpr uint16_t STUN_METHOD_SEND = 0x006;
  static constexpr uint16_t STUN_METHOD_DATA = 0x007;
  static constexpr uint16_t STUN_METHOD_CREATE_PERMISSION = 0x008;
  static constexpr uint16_t STUN_METHOD_CHANNEL_BIND = 0x009;

  constexpr method_t() : _val(0) {}
  constexpr method_t(uint16_t val) : _val(val) {}

  constexpr operator uint16_t() const { return _val; }
  constexpr operator uint16_t &() { return _val; }

private:
  uint16_t _val;
};

struct password_algorithm_t {
  static constexpr uint16_t STUN_PASSWORD_ALGORITHM_UNSET = 0x0000;
  static constexpr uint16_t STUN_PASSWORD_ALGORITHM_MD5 = 0x0001;
  static constexpr uint16_t STUN_PASSWORD_ALGORITHM_SHA256 = 0x0002;

  constexpr password_algorithm_t() : _val(STUN_PASSWORD_ALGORITHM_UNSET) {}
  constexpr password_algorithm_t(uint16_t val) : _val(val) {}

  constexpr operator uint16_t() const { return _val; }
  constexpr operator uint16_t &() { return _val; }

private:
  uint16_t _val;
};

constexpr bool stun_is_response(uint16_t msg_class) {
  return (msg_class & 0x0100) != 0;
}

// Nonce cookie prefix as specified in
// https://www.rfc-editor.org/rfc/rfc8489.html#section-9.2
#define STUN_NONCE_COOKIE "obMatJos2"
#define STUN_NONCE_COOKIE_LEN 9

// USERHASH is a SHA256 digest
#define USERHASH_SIZE 32

// STUN Security Feature bits as defined in
// https://www.rfc-editor.org/rfc/rfc8489.html#section-18.1 See errata about bit
// order: https://www.rfc-editor.org/errata_search.php?rfc=8489 Bits are
// assigned starting from the least significant side of the bit set, so Bit 0 is
// the rightmost bit, and Bit 23 is the leftmost bit. Bit 0: Password algorithms
// Bit 1: Username anonymity
// Bit 2-23: Unassigned

#define STUN_SECURITY_PASSWORD_ALGORITHMS_BIT 0x01
#define STUN_SECURITY_USERNAME_ANONYMITY_BIT 0x02

#define STUN_MAX_PASSWORD_ALGORITHMS_VALUE_SIZE 256

struct message {
  struct endpoint_t {
    net::ip::address address;
    uint16_t port{0};
  };

  struct error_code_t {
    uint16_t code;
    std::string reason;
  };

  struct integrity_t {
    enum algo_t { SHA1, SHA256 };
    bool verify(std::string_view password);
    algo_t algo() const noexcept { return _algo; }
    std::span<const std::byte> message_before_integrity() const noexcept {
      return {_msg, _hash_value.data() - 4};
    }
    std::span<const std::byte> hash_value() const noexcept {
      return _hash_value;
    }

  private:
    friend struct message;

    algo_t _algo{};
    const std::byte *_msg{};
    std::span<const std::byte> _hash_value{};
  };

  struct password_algorithm_t {
    static constexpr uint16_t MD5 = 1;
    static constexpr uint16_t SHA256 = 2;

    password_algorithm_t(uint16_t algo_type, std::span<const std::byte> param)
        : _algo{algo_type}, _value(param.begin(), param.end()) {
      if (_value.size() > 256)
        throw std::runtime_error{
            "password algorithm's parameter size greater than 256"};
    }

    uint16_t algo() const noexcept { return _algo; }
    std::span<const std::byte> parameter() const noexcept {
      return {_value.data(), _value.size()};
    }
    std::string get_hmac_key(std::string_view username, std::string_view realm,
                             std::string_view password);

  private:
    uint16_t _algo{};
    std::vector<std::byte> _value{};
  };

  int write_to(void *data, std::size_t length) const noexcept;
  bool parse(const void *data, std::size_t length,
             std::size_t *offset = nullptr) noexcept;
  static bool is_not_stun(const void *data, std::size_t length) noexcept;
  bool is_response() const noexcept { return (cls & 0x0100) != 0; }

  class_t cls{0};
  method_t method{0};

  std::array<uint8_t, 12> transaction_id{};
  std::optional<endpoint_t> mapped_address;
  std::optional<endpoint_t> xor_mapped_address;
  std::string username;
  mutable boost::container::small_vector<integrity_t, 2> integrities{};
  boost::container::small_vector<password_algorithm_t, 2> password_algorithms{};
  std::optional<error_code_t> error_code;
  std::string realm;
  std::string nonce;
  std::string software;
  std::optional<std::array<uint8_t, USERHASH_SIZE>> userhash;

  // ICE attributes
  std::optional<uint32_t> priority;

  // Tie-Breaker
  std::optional<uint64_t> ice_controlling;

  // Pseudo-Random
  std::optional<uint64_t> ice_controlled;

  // Candidate Address
  bool use_candidate{false};

  //
  std::optional<endpoint_t> changed_address;
  std::optional<uint16_t> channel_number;
  std::optional<uint32_t> lifetime;
  std::optional<endpoint_t> xor_peer_address;
  std::optional<endpoint_t> xor_relayed_address;
  bool requested_transport{false};
  std::optional<endpoint_t> response_origin;
  std::optional<endpoint_t> other_address;
  std::optional<endpoint_t> alternate_server;
  bool even_port{false};
  bool next_port{false};
  bool dont_fragment{false};
  std::optional<uint64_t> reservation_token;

  std::string password;

  std::string to_string();
  void reset() noexcept;
  const std::string &hmac_key() const noexcept { return _hmac_key; }
  void set_hmac_key(std::string_view key) noexcept { _hmac_key = key; }
  void use_fingerprint(bool use) noexcept { _use_fingerprint = use; }
  bool use_fingerprint() const noexcept { return _use_fingerprint; }
  void add_message_integrity(integrity_t::algo_t algo) {
    _integrity_algos.push_back(algo);
  }
  void remove_message_integrity() noexcept { _integrity_algos.clear(); }

private:
  bool _checked_fingerprint{false};
  std::string _hmac_key;
  bool _use_message_integrity{false};
  bool _use_fingerprint{false};
  boost::container::small_vector<integrity_t::algo_t, 2> _integrity_algos;
};

} // namespace ice::stun