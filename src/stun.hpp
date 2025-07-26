#pragma once

#include "config.hpp"
#include "address.hpp"
#include "endian.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
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
#include <vector>

namespace ice::stun {

inline constexpr std::size_t HEADER_SIZE = 20U;

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

// Nonce cookie prefix as specified in
// https://www.rfc-editor.org/rfc/rfc8489.html#section-9.2
inline constexpr std::string_view STUN_NONCE_COOKIE = "obMatJos2";

// USERHASH is a SHA256 digest
inline constexpr std::size_t USERHASH_SIZE = 32;

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
    struct error_code {
        uint16_t code;
        std::string reason;
    };

    struct integrity {
        enum algo_t { SHA1, SHA256 };

        integrity(algo_t algo) : _algo(algo) {}
        bool verify(std::string_view key, const void *data,
                    std::size_t size) const;
        bool verify(std::string_view key, const message &msg) const;
        algo_t algo() const noexcept { return _algo; }

        friend bool operator==(const integrity &lhs, const integrity &rhs) {
            return lhs._algo == rhs._algo;
        }

      private:
        friend struct message;

        algo_t _algo;
    };

    struct password_algorithm {
        static constexpr uint16_t MD5 = 1;
        static constexpr uint16_t SHA256 = 2;

        password_algorithm(uint16_t algo_type = MD5) noexcept
            : _algo{algo_type} {}

        password_algorithm(uint16_t algo_type, std::span<const std::byte> param)
            : _algo{algo_type}, _value(param.begin(), param.end()) {
            if (_value.size() > 256)
                throw std::runtime_error{
                    "password algorithm's parameter size greater than 256"};
        }

        password_algorithm(const password_algorithm &) = default;
        password_algorithm(password_algorithm &&) noexcept = default;
        password_algorithm &operator=(const password_algorithm &) = default;
        password_algorithm &operator=(password_algorithm &&) noexcept = default;

        uint16_t algo() const noexcept { return _algo; }
        const std::vector<std::byte> &parameter() const noexcept {
            return _value;
        }
        std::string get_hmac_key(std::string_view username,
                                 std::string_view realm,
                                 std::string_view password) const;
        bool supported() const noexcept {
            return _algo == MD5 || _algo == SHA256;
        }

      private:
        uint16_t _algo{};
        std::vector<std::byte> _value{};
    };

    std::string to_string();
    std::size_t serialized_size() const noexcept;
    void reset() noexcept;
    void fill_random_transaction_id();
    const std::string &hmac_key() const noexcept { return _hmac_key; }
    void set_hmac_key(std::string key) noexcept { _hmac_key = std::move(key); }
    void use_fingerprint(bool use) noexcept { _use_fingerprint = use; }
    bool use_fingerprint() const noexcept { return _use_fingerprint; }
    int write_to(void *data, std::size_t length) const noexcept;
    bool parse(const void *data, std::size_t length,
               std::size_t *offset = nullptr) noexcept;
    bool is_response() const noexcept { return (cls & 0x0100) != 0; }
    uint32_t security_features() const noexcept { return _security_features; }
    void set_security_features(uint32_t features) noexcept {
        _security_features = features;
    }
    void prepend_nonce_cookie();
    bool has_turn_data() const noexcept {
        return _turn_data || _reserved_turn_data;
    }
    const std::byte *turn_data() const noexcept { return _turn_data->data(); }
    std::size_t turn_data_size() const noexcept { return _turn_data->size(); }
    void reserve_turn_data(std::size_t size) noexcept {
        _reserved_turn_data = size;
    }
    bool has_reserved_turn_data() const noexcept {
        return !!_reserved_turn_data;
    }
    std::size_t reserved_turn_data_size() const noexcept {
        return *_reserved_turn_data;
    }
    std::byte *writable_turn_data() const noexcept {
        return _writable_turn_data;
    }

    static bool is_not_stun(const void *data, std::size_t length) noexcept;
    static const uint8_t *
    get_transaction_id(const void *data,
                       std::size_t length) noexcept(!ICE_DEBUG);
    static bool is_response(const void *data,
                            std::size_t length) noexcept(!ICE_DEBUG);
    static void compute_userhash(void *out, std::string_view username,
                                 std::string_view realm);
    static class_t get_class(const void *data,
                             std::size_t length) noexcept(!ICE_DEBUG);
    static method_t get_method(const void *data,
                               std::size_t length) noexcept(!ICE_DEBUG);

    class_t cls{0};
    method_t method{0};

    std::array<uint8_t, 12> transaction_id{};
    std::optional<endpoint> mapped_address;
    std::optional<endpoint> xor_mapped_address;
    std::string username;
    boost::container::small_vector<integrity, 2> integrities{};
    std::optional<password_algorithm> pwd_algorithm{};
    boost::container::small_vector<password_algorithm, 2> pwd_algorithms{};
    std::optional<error_code> error_code;
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
    std::optional<endpoint> changed_address;
    std::optional<uint16_t> channel_number;
    std::optional<uint32_t> lifetime; // seconds
    boost::container::small_vector<endpoint, 1> xor_peer_address;
    std::optional<endpoint> xor_relayed_address;
    bool requested_transport{false};
    std::optional<endpoint> response_origin;
    std::optional<endpoint> other_address;
    std::optional<endpoint> alternate_server;
    bool even_port{false};
    bool next_port{false};
    bool dont_fragment{false};
    std::optional<uint64_t> reservation_token;

  private:
    std::vector<std::byte> _raw_data;
    bool _checked_fingerprint{false};
    std::string _hmac_key;
    bool _use_fingerprint{false};
    uint32_t _security_features{0};
    std::optional<std::span<const std::byte>> _turn_data; // only for parsing
    std::optional<std::size_t> _reserved_turn_data;  // only for serializing
    mutable std::byte *_writable_turn_data{nullptr}; // only for serializing
};

} // namespace ice::stun