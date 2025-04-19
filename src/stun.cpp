#include "stun.hpp"
#include "base64.hpp"
#include "binary.hpp"
#include "hash.hpp"
#include "scope_guard.hpp"

#include "json.hpp"
#include <boost/crc.hpp>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <iterator>
#include <ranges>
#include <span>
#include <sstream>

namespace ice::stun {

#pragma pack(push, 1)
/*
 * STUN message header (20 bytes)
 * See https://www.rfc-editor.org/rfc/rfc8489.html#section-5
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |0 0|     STUN Message Type     |         Message Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Magic Cookie = 0x2112A442                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                     Transaction ID (96 bits)                  |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define STUN_TRANSACTION_ID_SIZE 12

struct header_t {
    uint16_t type{0};
    uint16_t length{0};
    uint32_t magic{0};
    uint8_t transaction_id[STUN_TRANSACTION_ID_SIZE];
};

static_assert(sizeof(header_t) == 20,
              "STUN message header size must be 20 bytes");

/*
 * Format of STUN Message Type Field
 *
 *  0                 1
 *  2  3  4 5 6 7 8 9 0 1 2 3 4 5
 * +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
 * |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
 * |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
 * +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
 * Request:    C=b00
 * Indication: C=b01
 * Response:   C=b10 (success)
 *             C=b11 (error)
 */
#define STUN_CLASS_MASK 0x0110
#define STUN_MAGIC 0x2112A442

/*
 * STUN attribute header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Value (variable)                     ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct attr_t {
    uint16_t type;
    uint16_t length;

    const uint8_t *value() const noexcept {
        return reinterpret_cast<const uint8_t *>(this) + 4;
    }

    uint8_t *value() noexcept { return reinterpret_cast<uint8_t *>(this) + 4; }

    uint8_t operator[](std::size_t i) const noexcept { return value()[i]; }

    uint8_t &operator[](std::size_t i) noexcept { return value()[i]; }
};

static_assert(sizeof(attr_t) == 4,
              "STUN attribute header size must be 4 bytes");

struct attr_type_t {
    // Comprehension-required
    static constexpr uint16_t STUN_ATTR_MAPPED_ADDRESS = 0x0001;
    static constexpr uint16_t STUN_ATTR_USERNAME = 0x0006;
    static constexpr uint16_t STUN_ATTR_MESSAGE_INTEGRITY = 0x0008;
    static constexpr uint16_t STUN_ATTR_ERROR_CODE = 0x0009;
    static constexpr uint16_t STUN_ATTR_UNKNOWN_ATTRIBUTES = 0x000A;
    static constexpr uint16_t STUN_ATTR_REALM = 0x0014;
    static constexpr uint16_t STUN_ATTR_NONCE = 0x0015;
    static constexpr uint16_t STUN_ATTR_MESSAGE_INTEGRITY_SHA256 = 0x001C;
    static constexpr uint16_t STUN_ATTR_PASSWORD_ALGORITHM = 0x001D;
    static constexpr uint16_t STUN_ATTR_USERHASH = 0x001E;
    static constexpr uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;
    static constexpr uint16_t STUN_ATTR_PRIORITY = 0x0024;
    static constexpr uint16_t STUN_ATTR_USE_CANDIDATE = 0x0025;

    // Comprehension-optional
    static constexpr uint16_t STUN_ATTR_PASSWORD_ALGORITHMS = 0x8002;
    static constexpr uint16_t STUN_ATTR_ALTERNATE_DOMAIN = 0x8003;
    static constexpr uint16_t STUN_ATTR_SOFTWARE = 0x8022;
    static constexpr uint16_t STUN_ATTR_ALTERNATE_SERVER = 0x8023;
    static constexpr uint16_t STUN_ATTR_FINGERPRINT = 0x8028;
    static constexpr uint16_t STUN_ATTR_ICE_CONTROLLED = 0x8029;
    static constexpr uint16_t STUN_ATTR_ICE_CONTROLLING = 0x802A;

    // Attributes for TURN
    // See https://www.rfc-editor.org/rfc/rfc8656.html#section-18
    static constexpr uint16_t STUN_ATTR_CHANNEL_NUMBER = 0x000C;
    static constexpr uint16_t STUN_ATTR_LIFETIME = 0x000D;
    static constexpr uint16_t STUN_ATTR_XOR_PEER_ADDRESS = 0x0012;
    static constexpr uint16_t STUN_ATTR_DATA = 0x0013;
    static constexpr uint16_t STUN_ATTR_XOR_RELAYED_ADDRESS = 0x0016;
    static constexpr uint16_t STUN_ATTR_EVEN_PORT = 0x0018;
    static constexpr uint16_t STUN_ATTR_REQUESTED_TRANSPORT = 0x0019;
    static constexpr uint16_t STUN_ATTR_DONT_FRAGMENT = 0x001A;
    static constexpr uint16_t STUN_ATTR_RESERVATION_TOKEN = 0x0022;

    constexpr attr_type_t() : _val(0) {}
    constexpr attr_type_t(uint16_t val) : _val(val) {}

    constexpr operator uint16_t() const { return _val; }
    constexpr operator uint16_t &() { return _val; }

  private:
    uint16_t _val;
};

constexpr bool is_optional_attr(uint16_t attr_type) {
    return !!(attr_type & 0x8000);
}

struct address_family_t {
    static constexpr uint8_t STUN_ADDRESS_FAMILY_IPV4 = 0x01;
    static constexpr uint8_t STUN_ADDRESS_FAMILY_IPV6 = 0x02;

    constexpr address_family_t() : _val(0) {}
    constexpr address_family_t(uint8_t val) : _val(val) {}

    constexpr operator uint8_t() const { return _val; }

    constexpr operator uint8_t &() { return _val; }

  private:
    uint8_t _val;
};

/*
 * STUN attribute value for ERROR-CODE
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Reserved, should be 0         |Class|     Number    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Reason Phrase (variable)                               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct value_error_code_t {
#ifdef __ICE_LITTLE_ENDIAN__
    uint16_t reserved{0};
    uint8_t code_class : 3 {0};
    uint8_t zero : 5 {0};
    uint8_t code_number{0};
#else
    uint16_t reserved{0};
    uint8_t zero : 5 {0};
    uint8_t code_class : 3 {0};
    uint8_t code_number{0};
#endif

    const char *reason() const noexcept {
        return reinterpret_cast<const char *>(this) + 4;
    }

    char *reason() noexcept { return reinterpret_cast<char *>(this) + 4; }

    char operator[](size_t i) const noexcept { return reason()[i]; }

    char &operator[](size_t i) noexcept { return reason()[i]; }
};

static_assert(sizeof(value_error_code_t) == 4,
              "value_error_code_t size must be 4 bytes");

#define STUN_ERROR_INTERNAL_VALIDATION_FAILED 599

/*
 * STUN attribute for CHANNEL-NUMBER
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Channel Number         |         RFFU = 0              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct value_channel_number_t {
    uint16_t channel_number{0};
    uint16_t reserved{0};
};

static_assert(sizeof(value_channel_number_t) == 4,
              "value_channel_number_t size must be 4 bytes");

/*
 * STUN attribute for EVEN-PORT
 *
 *  0
 *  0 1 2 3 4 5 6 7
 * +-+-+-+-+-+-+-+-+
 * |R|    RFFU     |
 * +-+-+-+-+-+-+-+-+
 */
struct value_even_port_t {
#ifdef __ICE_BIG_ENDIAN__
    uint8_t r : 1 {0};
    uint8_t reserved : 7 {0};
#else
    uint8_t reserved : 7 {0};
    uint8_t r : 1 {0};
#endif
};

static_assert(sizeof(value_even_port_t) == 1,
              "value_even_port_t size must be 1 bytes");

/*
 * STUN attribute for REQUESTED-TRANSPORT
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Protocol   |                    RFFU                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct value_requested_transport_t {
    uint8_t protocol{0};
    uint8_t reserved1{0};
    uint16_t reserved2{0};
};

static_assert(sizeof(value_requested_transport_t) == 4,
              "value_requested_transport_t size must be 4 bytes");

/*
 * STUN attribute value for PASSWORD-ALGORITHM and PASSWORD-ALGORITHMS
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Algorithm 1           | Algorithm 1 Parameters Length |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Algorithm 1 Parameters (variable)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Algorithm 2           | Algorithm 2 Parameters Length |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Algorithm 2 Parameters (variable)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                             ...
 */
struct value_password_algorithm_t {
    uint16_t algorithm{0};
    uint16_t parameters_length{0};

    const uint8_t *parameters() const noexcept {
        return reinterpret_cast<const uint8_t *>(this) + 4;
    }

    uint8_t *parameters() noexcept {
        return reinterpret_cast<uint8_t *>(this) + 4;
    }

    uint8_t operator[](std::size_t i) const noexcept { return parameters()[i]; }

    uint8_t &operator[](std::size_t i) noexcept { return parameters()[i]; }
};

static_assert(sizeof(value_password_algorithm_t) == 4,
              "value_password_algorithm_t size must be 4 bytes");

/*
 * STUN attribute value for MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |X X X X X X X X|    Family     |        Port or X-Port         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |           Address or X-Address (32 bits or 128 bits)          |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct value_mapped_address_t {
    uint8_t pad{0};
    uint8_t family{0};
    uint16_t port{0};

    const uint8_t *address() const noexcept {
        return reinterpret_cast<const uint8_t *>(this) + 4;
    }

    uint8_t *address() noexcept {
        return reinterpret_cast<uint8_t *>(this) + 4;
    }

    uint8_t operator[](std::size_t i) const noexcept { return address()[i]; }

    uint8_t &operator[](std::size_t i) noexcept { return address()[i]; }
};

static_assert(sizeof(value_mapped_address_t) == 4);

#pragma pack(pop)

struct attr_iterator_sentinel_t {
    attr_iterator_sentinel_t() noexcept {
        _end = std::numeric_limits<std::uintptr_t>::max();
    }

    attr_iterator_sentinel_t(const void *p) noexcept
        : _end{reinterpret_cast<std::uintptr_t>(p)} {}

    const uint8_t *data() const noexcept {
        return reinterpret_cast<const uint8_t *>(_end);
    }

  private:
    friend struct attr_iterator_t;
    friend struct const_attr_iterator_t;

    std::uintptr_t _end;
};

struct attr_iterator_t {
    using difference_type = std::ptrdiff_t;
    using value_type = attr_t;
    using reference = attr_t &;
    using const_reference = const attr_t &;

    attr_iterator_t(void *attr = nullptr) noexcept
        : _current{reinterpret_cast<attr_t *>(attr)} {}

    attr_t &operator*() const noexcept { return *_current; }

    const attr_t *operator->() const noexcept { return _current; }

    attr_t *operator->() noexcept { return _current; }

    attr_iterator_t &operator++() noexcept {
        uint16_t len = binary::ntoh<uint16_t>(_current->length) + 4;
        if (len & 0x3)
            len += 4 - (len & 0x3);
        _current = reinterpret_cast<attr_t *>(
            reinterpret_cast<uint8_t *>(_current) + len);
        return *this;
    }

    attr_iterator_t operator++(int) noexcept {
        auto tmp = *this;
        ++*this;
        return tmp;
    }

    bool operator==(const attr_iterator_sentinel_t &s) const noexcept {
        return reinterpret_cast<std::uintptr_t>(_current) + 4 > s._end;
    }

    uint8_t *data() noexcept { return reinterpret_cast<uint8_t *>(_current); }
    const uint8_t *data() const noexcept {
        return reinterpret_cast<const uint8_t *>(_current);
    }

  private:
    attr_t *_current;
};

struct const_attr_iterator_t {
    using difference_type = std::ptrdiff_t;
    using value_type = attr_t;
    using const_reference = const attr_t &;

    const_attr_iterator_t(const void *attr = nullptr) noexcept
        : _current{reinterpret_cast<const attr_t *>(attr)} {}

    const attr_t &operator*() const noexcept { return *_current; }

    const attr_t *operator->() const noexcept { return _current; }

    const_attr_iterator_t &operator++() noexcept {
        uint16_t len = binary::ntoh<uint16_t>(_current->length) + 4;
        if (len & 0x3)
            len += 4 - (len & 0x3);
        _current = reinterpret_cast<const attr_t *>(
            reinterpret_cast<const uint8_t *>(_current) + len);
        return *this;
    }

    const_attr_iterator_t operator++(int) noexcept {
        auto tmp = *this;
        ++*this;
        return tmp;
    }

    bool operator==(const attr_iterator_sentinel_t &s) const noexcept {
        return reinterpret_cast<std::uintptr_t>(_current) + 4 > s._end;
    }

    const uint8_t *data() const noexcept {
        return reinterpret_cast<const uint8_t *>(_current);
    }

  private:
    const attr_t *_current;
};

static_assert(std::input_iterator<attr_iterator_t>);
static_assert(std::input_iterator<const_attr_iterator_t>);
static_assert(std::sentinel_for<attr_iterator_sentinel_t, attr_iterator_t>);
static_assert(
    std::sentinel_for<attr_iterator_sentinel_t, const_attr_iterator_t>);

static int parse_address(const void *data, std::size_t buf_size,
                         endpoint &address) {
    uint8_t pad = 0;
    uint8_t protocol = 0;
    uint16_t port = 0;
    std::error_code ec;
    if (binary::unpack<"!BBH">(data, buf_size, ec, pad, protocol, port);
        ec || pad != 0)
        return -1;
    const uint8_t *iter = reinterpret_cast<const uint8_t *>(data) + 4;
    const uint8_t *const end =
        reinterpret_cast<const uint8_t *>(data) + buf_size;
    if (protocol == 1) {
        // IPv4
        if (iter + 4 > end)
            return -1;
        net::ip::address_v4::bytes_type bytes;
        std::copy(iter, iter + 4, bytes.begin());
        address.address = net::ip::address_v4(bytes);
        address.port = port;
        return 8;
    } else if (protocol == 2) {
        // IPv6
        if (iter + 16 > end)
            return -1;
        net::ip::address_v6::bytes_type bytes;
        std::copy(iter, iter + 16, bytes.data());
        address.address = net::ip::address_v6(bytes);
        address.port = port;
        return 4 + 16;
    }
    return -1;
}

static int parse_xor_address(const void *data, std::size_t buf_size,
                             const header_t *header, endpoint &address) {
    if (buf_size < 4)
        return -1;
    const value_mapped_address_t *mapped_address =
        reinterpret_cast<const value_mapped_address_t *>(data);
    if (mapped_address->pad != 0)
        return -1;
    if (binary::ntoh<uint8_t>(mapped_address->family) == 1) {
        // IPv4
        if (4 + 4 > buf_size)
            return -1;
        address.port = binary::ntoh<uint16_t>(
            mapped_address->port ^
            *reinterpret_cast<const uint16_t *>(&header->magic));
        address.address = net::ip::address_v4(binary::ntoh<uint32_t>(
            *reinterpret_cast<const uint32_t *>(mapped_address->address()) ^
            header->magic));
        return 4 + 4;
    } else if (binary::ntoh<uint8_t>(mapped_address->family) == 2) {
        // IPv6
        if (4 + 16 > buf_size)
            return -1;
        net::ip::address_v6::bytes_type bytes;
        address.port = binary::ntoh<uint16_t>(
            mapped_address->port ^
            *reinterpret_cast<const uint16_t *>(&header->magic));
        const uint32_t *v32 =
            reinterpret_cast<const uint32_t *>(mapped_address->address());
        uint32_t *a32 = reinterpret_cast<uint32_t *>(bytes.data());
        const uint32_t *mask =
            reinterpret_cast<const uint32_t *>(&header->magic);
        for (int i = 0; i < 4; ++i)
            a32[i] = v32[i] ^ mask[i];
        address.address = net::ip::address_v6(bytes);
        return 4 + 16;
    }
    return -1;
}

static const attr_t *find_attr(const void *data, std::size_t size,
                               uint16_t type) noexcept {
    const uint8_t *begin = static_cast<const uint8_t *>(data);
    const_attr_iterator_t iter{begin + 20};
    const attr_iterator_sentinel_t end{begin + size};
    for (; iter != end; ++iter) {
        if (binary::ntoh<uint16_t>(iter->type) == type)
            return &*iter;
    }
    return nullptr;
}

bool message::integrity::verify(std::string_view password, const void *data,
                                std::size_t size) const {
    ICE_IN_DEBUG {
        std::cout << "Check message integrity with key: " << password << '\n';
        if (message::is_not_stun(data, size)) {
            std::cout << "Not STUN message\n";
            throw std::runtime_error("Not STUN message");
        }
    };
    const attr_t *attr =
        find_attr(data, size,
                  _algo == algo_t::SHA1
                      ? attr_type_t::STUN_ATTR_MESSAGE_INTEGRITY
                      : attr_type_t::STUN_ATTR_MESSAGE_INTEGRITY_SHA256);
    if (!attr) {
        ICE_IN_DEBUG { std::cout << "No message integrity attribute\n"; }
        return false;
    }
    const uint8_t *begin = static_cast<const uint8_t *>(data);
    const uint8_t *const end = begin + size;
    const uint16_t hash_size = binary::ntoh<uint16_t>(attr->length);
    if (hash_size + 4 + (const uint8_t *)attr > end) {
        ICE_IN_DEBUG {
            std::cout << "Message integrity attribute length is invalid\n";
        }
        return false;
    }
    uint16_t tmp_len = binary::hton<uint16_t>(
        (uint16_t)((const uint8_t *)attr - begin - 20 + 4 + hash_size));
    if (_algo == algo_t::SHA1) {
        if (hash_size != hash::sha1::digest_size)
            return false;
        char res[hash::sha1::digest_size];
        hash::hmac_context<hash::sha1> ctx(password);
        ctx.update(begin, 2);
        ctx.update(&tmp_len, 2);
        ctx.update(begin + 4, (const uint8_t *)attr - begin - 4);
        ctx.final(res, sizeof(res));
        if (std::memcmp(res, attr->value(), hash_size) != 0)
            return false;
    } else if (_algo == algo_t::SHA256) {
        if (hash_size != hash::sha256::digest_size)
            return false;
        char res[hash::sha256::digest_size];
        hash::hmac_context<hash::sha256> ctx(password);
        ctx.update(begin, 2);
        ctx.update(&tmp_len, 2);
        ctx.update(begin + 4, (const uint8_t *)attr - begin - 4);
        ctx.final(res, sizeof(res));
        if (std::memcmp(res, attr->value(), hash_size) != 0)
            return false;
    } else {
        ICE_IN_DEBUG { std::cout << "Unknown message integrity algorithm\n"; }
        return false;
    }
    ICE_IN_DEBUG { std::cout << "Message integrity check success\n" << '\n'; }
    return true;
}

bool message::integrity::verify(std::string_view key,
                                const message &msg) const {
    ICE_IN_DEBUG {
        if (msg._raw_data.empty() ||
            is_not_stun(msg._raw_data.data(), msg._raw_data.size())) {
            std::cout << "Message integrity check failed: not a STUN message\n";
            throw std::runtime_error(
                "Message integrity check failed: not a STUN message");
        }
    }
    return verify(key, msg._raw_data.data(), msg._raw_data.size());
}

std::string
message::password_algorithm::get_hmac_key(std::string_view username,
                                          std::string_view realm,
                                          std::string_view password) const {
    std::string input;
    input.resize_and_overwrite(
        username.size() + realm.size() + password.size() + 2 + 32,
        [&](char *p, std::size_t n) -> std::size_t {
            p += 32;
            p = std::copy(username.begin(), username.end(), p);
            *p++ = ':';
            p = std::copy(realm.begin(), realm.end(), p);
            *p++ = ':';
            p = std::copy(password.begin(), password.end(), p);

            if (_algo == password_algorithm::SHA256) {
                hash::SHA256(input.data(),
                             std::string_view{input.data() + 32,
                                              static_cast<std::size_t>(
                                                  p - input.data() - 32)});
            } else {
                hash::MD5(input.data(),
                          std::string_view{
                              input.data() + 32,
                              static_cast<std::size_t>(p - input.data() - 32)});
            }
            return _algo == password_algorithm::SHA256
                       ? hash::sha256::digest_size
                       : hash::md5::digest_size;
        });
    return input;
}

bool message::parse(const void *data, std::size_t buf_size,
                    std::size_t *offset) noexcept {
    if (offset) {
        if (*offset >= buf_size)
            return false;
        data = reinterpret_cast<const char *>(data) + *offset;
        buf_size -= *offset;
    }
    if (buf_size < sizeof(header_t))
        return false;
    const header_t *header = static_cast<const header_t *>(data);
    const std::size_t len = binary::ntoh<uint16_t>(header->length);
    if (len + sizeof(header_t) > buf_size)
        return false;
    if (binary::ntoh<uint32_t>(header->magic) != STUN_MAGIC)
        return false;
    uint16_t type = binary::ntoh<uint16_t>(header->type);
    this->cls = type & STUN_CLASS_MASK;
    this->method = type & ~STUN_CLASS_MASK;
    std::copy_n(header->transaction_id, 12, transaction_id.data());

    const uint8_t *begin = reinterpret_cast<const uint8_t *>(data);
    const_attr_iterator_t iter{begin + 20};
    const attr_iterator_sentinel_t end{begin + 20 + len};
    bool fingerprint = false;

    for (; iter != end; ++iter) {
        utils::scope_guard update_offset{[&]() noexcept {
            if (offset) {
                *offset += (iter.data() - begin);
            }
        }};
        if (fingerprint)
            return false;
        const attr_t &attr = *iter;
        const uint16_t attr_type = binary::ntoh<uint16_t>(attr.type);
        const uint16_t attr_len = binary::ntoh<uint16_t>(attr.length);
        if (attr_len + 4 + iter.data() > end.data())
            return false;
        if (!this->integrities.empty() &&
            attr_type != attr_type_t::STUN_ATTR_MESSAGE_INTEGRITY &&
            attr_type != attr_type_t::STUN_ATTR_MESSAGE_INTEGRITY_SHA256 &&
            attr_type != attr_type_t::STUN_ATTR_FINGERPRINT) {
            goto END;
        }
        switch (attr_type) {
        case attr_type_t::STUN_ATTR_MAPPED_ADDRESS: {
            if ((attr_len != 8 && attr_len != 20) ||
                parse_address(attr.value(), end.data() - attr.value(),
                              this->mapped_address.emplace()) != attr_len)
                return false;
            break;
        }
        case attr_type_t::STUN_ATTR_XOR_MAPPED_ADDRESS: {
            if ((attr_len != 8 && attr_len != 20) ||
                parse_xor_address(attr.value(), end.data() - attr.value(),
                                  header, this->xor_mapped_address.emplace()) !=
                    attr_len)
                return false;
            break;
        }
        case attr_type_t::STUN_ATTR_ALTERNATE_SERVER: {
            if ((attr_len != 8 && attr_len != 20) ||
                parse_address(attr.value(), end.data() - attr.value(),
                              this->alternate_server.emplace()) != attr_len)
                return false;
            break;
        }
        case attr_type_t::STUN_ATTR_ERROR_CODE: {
            if (attr_len < sizeof(value_error_code_t))
                return false;
            this->error_code.emplace();
            auto *ec =
                reinterpret_cast<const value_error_code_t *>(attr.value());
            this->error_code->code = ec->code_class * 100 + ec->code_number;
            if (attr_len > sizeof(value_error_code_t) + 762)
                return false;
            if (attr_len > sizeof(value_error_code_t))
                this->error_code->reason = std::string_view{
                    ec->reason(), static_cast<std::size_t>(attr_len - 4)};
            break;
        }
        case attr_type_t::STUN_ATTR_UNKNOWN_ATTRIBUTES: {
            break;
        }
        case attr_type_t::STUN_ATTR_USERNAME: {
            if (attr_len > 513)
                return false;
            this->username = std::string_view{
                reinterpret_cast<const char *>(attr.value()), attr_len};
            break;
        }
        case attr_type_t::STUN_ATTR_MESSAGE_INTEGRITY: {
            if (attr_len == 0 || attr_len != hash::sha1::digest_size)
                return false;
            this->integrities.emplace_back(integrity::SHA1);
            break;
        }
        case attr_type_t::STUN_ATTR_MESSAGE_INTEGRITY_SHA256: {
            if (attr_len == 0 || attr_len != 32)
                return false;
            this->integrities.emplace_back(integrity::SHA256);
            break;
        }
        case attr_type_t::STUN_ATTR_FINGERPRINT: {
            ICE_IN_DEBUG { std::cout << "Check fingerprint\n"; }
            if (attr_len != 4)
                return false;
            fingerprint = true;
            uint16_t tmp_len = binary::hton<uint16_t>(iter.data() - begin -
                                                      sizeof(header_t) + 4 + 4);
            boost::crc_32_type crc;
            crc.process_bytes(begin, 2);
            crc.process_bytes(&tmp_len, 2);
            crc.process_bytes(begin + 4, iter.data() - begin - 4);
            if ((crc.checksum() ^ 0x5354554e) !=
                binary::read_big<uint32_t>(attr.value())) {
                ICE_IN_DEBUG {
                    std::cerr << "STUN fingerprint check failed.\n";
                }
                return false;
            }
            this->_checked_fingerprint = true;
            break;
        }
        case attr_type_t::STUN_ATTR_REALM: {
            if (attr_len > 763 || attr_len == 0)
                return false;
            this->realm = std::string_view{
                reinterpret_cast<const char *>(attr.value()), attr_len};
            break;
        }
        case attr_type_t::STUN_ATTR_NONCE: {
            if (attr_len > 763 || attr_len == 0)
                return false;
            this->nonce = std::string_view{
                reinterpret_cast<const char *>(attr.value()), attr_len};
            if (nonce.length() > STUN_NONCE_COOKIE.length() + 4 &&
                nonce.starts_with(STUN_NONCE_COOKIE)) {
                uint8_t bytes[4] = {0};
                auto [n_out, n_in] = base64::decode(
                    bytes + 1, nonce.data() + STUN_NONCE_COOKIE.length(), 4);
                if (n_in != 4 || n_out != 3) {
                    _security_features = 0;
                    ICE_IN_DEBUG {
                        std::cerr << "Nonce has cookie, but the encoded "
                                     "Security Feature bits field is invalid: "
                                  << this->nonce << '\n';
                    }
                } else {
                    _security_features = binary::read_big<uint32_t>(bytes);
                    ICE_IN_DEBUG {
                        std::cout
                            << "STUN: Security features: " << _security_features
                            << '\n';
                    }
                }
            }
            break;
        }
        case attr_type_t::STUN_ATTR_PASSWORD_ALGORITHM: {
            if (attr_len < sizeof(value_password_algorithm_t))
                return false;
            const auto *value_pwd_algo =
                reinterpret_cast<const value_password_algorithm_t *>(
                    attr.value());
            const uint16_t pwd_algo_type =
                binary::ntoh<uint16_t>(value_pwd_algo->algorithm);
            const auto pwd_algo_len =
                binary::ntoh<uint16_t>(value_pwd_algo->parameters_length);
            if (pwd_algo_len > 256 ||
                sizeof(value_password_algorithm_t) + pwd_algo_len > attr_len)
                return false;
            ICE_IN_DEBUG {
                if (pwd_algo_type != password_algorithm::MD5 &&
                    pwd_algo_type != password_algorithm::SHA256) {
                    std::cerr << "Unknown password algorithm:" << pwd_algo_type
                              << '\n';
                }
            }
            this->pwd_algorithm.emplace(
                pwd_algo_type,
                std::span<const std::byte>{reinterpret_cast<const std::byte *>(
                                               value_pwd_algo->parameters()),
                                           pwd_algo_len});
            break;
        }
        case attr_type_t::STUN_ATTR_PASSWORD_ALGORITHMS: {
            if (attr_len < sizeof(value_password_algorithm_t))
                return false;
            const_attr_iterator_t pwd_it{attr.value()};
            const attr_iterator_sentinel_t pwd_end{attr.value() + attr_len};
            for (; pwd_it != pwd_end; ++pwd_it) {
                const auto *value_pwd_algo =
                    reinterpret_cast<const value_password_algorithm_t *>(
                        pwd_it.data());
                const uint16_t pwd_algo_type =
                    binary::ntoh<uint16_t>(value_pwd_algo->algorithm);
                const auto pwd_algo_len =
                    binary::ntoh<uint16_t>(value_pwd_algo->parameters_length);
                if (pwd_algo_len > 256 ||
                    pwd_it.data() + sizeof(value_password_algorithm_t) +
                            pwd_algo_len >
                        pwd_end.data())
                    return false;
                ICE_IN_DEBUG {
                    if (pwd_algo_type != password_algorithm::MD5 &&
                        pwd_algo_type != password_algorithm::SHA256) {
                        std::cerr
                            << "Unknown password algorithm:" << pwd_algo_type
                            << '\n';
                    }
                }
                this->pwd_algorithms.emplace_back(
                    pwd_algo_type, std::span<const std::byte>{
                                       reinterpret_cast<const std::byte *>(
                                           value_pwd_algo->parameters()),
                                       pwd_algo_len});
            }
            if (pwd_it.data() != pwd_end.data())
                return false;
            break;
        }
        case attr_type_t::STUN_ATTR_USERHASH: {
            if (attr_len != USERHASH_SIZE)
                return false;
            std::copy_n(attr.value(), USERHASH_SIZE,
                        this->userhash.emplace().data());
            break;
        }
        case attr_type_t::STUN_ATTR_SOFTWARE: {
            if (attr_len > 763)
                return false;
            this->software = std::string_view{
                reinterpret_cast<const char *>(attr.value()), attr_len};
            break;
        }
        case attr_type_t::STUN_ATTR_PRIORITY: {
            if (attr_len != 4)
                return false;
            this->priority = binary::read_big<uint32_t>(attr.value());
            break;
        }
        case attr_type_t::STUN_ATTR_USE_CANDIDATE: {
            if (attr_len != 0)
                return false;
            this->use_candidate = true;
            break;
        }
        case attr_type_t::STUN_ATTR_ICE_CONTROLLING: {
            if (attr_len != 8)
                return false;
            this->ice_controlling =
                (static_cast<uint64_t>(binary::read_big<uint32_t>(attr.value()))
                 << 32) |
                binary::read_big<uint32_t>(attr.value() + 4);
            break;
        }
        case attr_type_t::STUN_ATTR_ICE_CONTROLLED: {
            if (attr_len != 8)
                return false;
            const uint32_t *v32 =
                reinterpret_cast<const uint32_t *>(attr.value());
            this->ice_controlled =
                (static_cast<uint64_t>(binary::ntoh<uint32_t>(v32[0])) << 32) |
                binary::ntoh<uint32_t>(v32[1]);
            break;
        }
        case attr_type_t::STUN_ATTR_CHANNEL_NUMBER: {
            if (attr_len != sizeof(value_channel_number_t))
                return false;
            const auto *channel_num =
                reinterpret_cast<const value_channel_number_t *>(attr.value());
            if (channel_num->reserved != 0)
                return false;
            this->channel_number =
                binary::ntoh<uint16_t>(channel_num->channel_number);
            break;
        }
        case attr_type_t::STUN_ATTR_LIFETIME: {
            if (attr_len != 4)
                return false;
            this->lifetime = binary::ntoh<uint32_t>(
                *reinterpret_cast<const uint32_t *>(attr.value()));
            break;
        }
        case attr_type_t::STUN_ATTR_XOR_PEER_ADDRESS: {
            ice::endpoint peer_addr;
            if ((attr_len != 8 && attr_len != 20) ||
                parse_xor_address(attr.value(), end.data() - attr.value(),
                                  header, peer_addr) != attr_len)
                return false;
            this->xor_peer_address.push_back(peer_addr);
            break;
        }
        case attr_type_t::STUN_ATTR_XOR_RELAYED_ADDRESS: {
            if ((attr_len != 8 && attr_len != 20) ||
                parse_xor_address(
                    attr.value(), end.data() - attr.value(), header,
                    this->xor_relayed_address.emplace()) != attr_len)
                return false;
            break;
        }
        case attr_type_t::STUN_ATTR_DATA: {
            break;
        }
        case attr_type_t::STUN_ATTR_EVEN_PORT: {
            if (attr_len < 1)
                return false;
            const value_even_port_t *e =
                reinterpret_cast<const value_even_port_t *>(attr.value());
            if (e->reserved != 0)
                return false;
            this->even_port = e->r & 0x80;
            break;
        }
        case attr_type_t::STUN_ATTR_REQUESTED_TRANSPORT: {
            if (attr_len != sizeof(value_requested_transport_t))
                return false;
            const auto *r =
                reinterpret_cast<const value_requested_transport_t *>(
                    attr.value());
            if (r->protocol != 17)
                return false;
            this->requested_transport = true;
            break;
        }
        case attr_type_t::STUN_ATTR_DONT_FRAGMENT: {
            if (attr_len != 0)
                return false;
            this->dont_fragment = true;
            break;
        }
        case attr_type_t::STUN_ATTR_RESERVATION_TOKEN: {
            if (attr_len != 8)
                return false;
            const uint32_t *v32 =
                reinterpret_cast<const uint32_t *>(attr.value());
            this->reservation_token =
                (static_cast<uint64_t>(binary::ntoh<uint32_t>(v32[0])) << 32) |
                binary::ntoh<uint32_t>(v32[1]);
            break;
        }
        default:
            // Ignore
            break;
        }
        update_offset.dismiss();
        if (offset)
            *offset += (iter.data() - begin) + attr_len + 4;
    }

    if (iter.data() - begin != len + sizeof(header_t))
        return false;
END:
    if (!this->integrities.empty()) {
        _raw_data.resize(sizeof(header_t) + len);
        std::memcpy(_raw_data.data(), data, sizeof(header_t) + len);
    }
    return true;
}

static int write_header(void *buf, size_t size, class_t cls, method_t method,
                        const uint8_t *transaction_id) {
    if (size < sizeof(header_t))
        return -1;

    uint16_t type = static_cast<uint16_t>(cls) | static_cast<uint16_t>(method);

    header_t *header = reinterpret_cast<header_t *>(buf);
    header->type = binary::hton<uint16_t>(type);
    header->length = 0;
    header->magic = binary::hton<uint32_t>(0x2112A442);
    std::memcpy(header->transaction_id, transaction_id,
                STUN_TRANSACTION_ID_SIZE);

    return sizeof(header_t);
}

static int write_address(void *data, std::size_t buf_size,
                         const endpoint &address) {
    if (buf_size < sizeof(value_mapped_address_t))
        return -1;
    value_mapped_address_t *mapped =
        reinterpret_cast<value_mapped_address_t *>(data);
    mapped->port = binary::hton<uint16_t>(address.port);
    mapped->pad = 0;
    if (address.address.is_v4()) {
        if (4 + 4 > buf_size)
            return -1;
        mapped->family = 1;
        binary::write_big<uint32_t>(mapped->address(),
                                    address.address.to_v4().to_uint());
        return 4 + 4;
    } else if (address.address.is_v6()) {
        if (4 + 16 > buf_size)
            return -1;
        mapped->family = 2;
        auto bytes = address.address.to_v6().to_bytes();
        std::memcpy(mapped->address(), bytes.data(), bytes.size());
        return 4 + 16;
    }
    return -1;
}

static int write_xor_address(void *data, std::size_t buf_size,
                             const header_t *header, const endpoint &address) {
    if (buf_size < sizeof(value_mapped_address_t))
        return -1;
    value_mapped_address_t *mapped =
        reinterpret_cast<value_mapped_address_t *>(data);
    mapped->port = header->magic ^ binary::hton<uint16_t>(address.port);
    mapped->pad = 0;
    if (address.address.is_v4()) {
        if (4 + 4 > buf_size)
            return -1;
        mapped->family = 1;
        uint32_t *value = reinterpret_cast<uint32_t *>(mapped->address());
        *value = header->magic ^
                 binary::hton<uint32_t>(address.address.to_v4().to_uint());
        return 4 + 4;
    } else if (address.address.is_v6()) {
        if (4 + 16 > buf_size)
            return -1;
        mapped->family = 2;
        auto bytes = address.address.to_v6().to_bytes();
        const uint32_t *mask =
            reinterpret_cast<const uint32_t *>(&header->magic);
        uint32_t *value = reinterpret_cast<uint32_t *>(mapped->address());
        for (int i = 0; i < 4; ++i)
            value[i] =
                mask[i] ^ reinterpret_cast<const uint32_t *>(bytes.data())[i];
        return 4 + 16;
    }
    return -1;
}

int message::write_to(void *buf, size_t length) const noexcept {
    int len = write_header(buf, length, this->cls, this->method,
                           this->transaction_id.data());
    if (len < 0)
        return -1;
    header_t *header = reinterpret_cast<header_t *>(buf);
    uint8_t *const buf_begin = reinterpret_cast<uint8_t *>(buf);
    const uint8_t *const buf_end = buf_begin + length;

    attr_iterator_t iter{buf_begin + len};
    attr_iterator_sentinel_t end{buf_end};

    if (this->error_code) {
        if (iter == end)
            goto overflow;
        uint16_t attr_size =
            sizeof(value_error_code_t) + this->error_code->reason.size();
        if (iter->value() + attr_size > buf_end)
            goto overflow;
        iter->type = binary::hton<uint16_t>(attr_type_t::STUN_ATTR_ERROR_CODE);
        iter->length = binary::hton<uint16_t>(attr_size);

        value_error_code_t *ec =
            reinterpret_cast<value_error_code_t *>(iter.data());
        ec->reserved = 0;
        auto r = std::div(this->error_code->code, 100);
        ec->code_class = r.quot & 0x07;
        ec->code_number = r.rem;
        std::ranges::copy(this->error_code->reason, ec->reason());
        ++iter;
    }

    if (this->mapped_address) {
        if (iter == end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_MAPPED_ADDRESS);
        auto attr_size = write_address(iter->value(), buf_end - iter->value(),
                                       *this->mapped_address);
        if (attr_size < 0)
            goto overflow;
        iter->length = binary::hton<uint16_t>(static_cast<uint16_t>(attr_size));
        ++iter;
    }

    if (this->xor_mapped_address) {
        if (iter == end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_XOR_MAPPED_ADDRESS);
        auto attr_size =
            write_xor_address(iter->value(), buf_end - iter->value(), header,
                              *this->xor_mapped_address);
        if (attr_size < 0)
            goto overflow;
        iter->length = binary::hton<uint16_t>(static_cast<uint16_t>(attr_size));
        ++iter;
    }

    if (!this->username.empty()) {
        if (iter == end)
            goto overflow;
        if (this->username.size() > 513)
            goto overflow;
        if (iter->value() + this->username.size() > buf_end)
            goto overflow;
        iter->type = binary::hton<uint16_t>(attr_type_t::STUN_ATTR_USERNAME);
        iter->length = binary::hton<uint16_t>((uint16_t)this->username.size());
        std::ranges::copy(this->username, (char *)iter->value());
        ++iter;
    }

    if (this->pwd_algorithm) {
        if (iter == end)
            goto overflow;
        if (iter->value() + sizeof(value_password_algorithm_t) +
                this->pwd_algorithm->parameter().size() >
            buf_end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_PASSWORD_ALGORITHM);
        iter->length =
            binary::hton<uint16_t>(sizeof(value_password_algorithm_t) +
                                   this->pwd_algorithm->parameter().size());
        auto *p = reinterpret_cast<value_password_algorithm_t *>(iter->value());
        p->algorithm = binary::hton<uint16_t>(this->pwd_algorithm->algo());
        p->parameters_length =
            binary::hton<uint16_t>(this->pwd_algorithm->parameter().size());
        std::ranges::copy(this->pwd_algorithm->parameter(),
                          (std::byte *)p->parameters());
        ++iter;
    }

    if (!this->pwd_algorithms.empty()) {
        if (iter == end)
            goto overflow;
        attr_iterator_t sub_it{iter->value()};
        attr_iterator_sentinel_t sub_end = end;
        for (const auto &pwd_algo : this->pwd_algorithms) {
            if (sub_it == sub_end)
                goto overflow;
            if (sub_it->value() + pwd_algo.parameter().size() > buf_end)
                goto overflow;
            auto *p =
                reinterpret_cast<value_password_algorithm_t *>(sub_it.data());
            p->algorithm = binary::hton<uint16_t>(pwd_algo.algo());
            p->parameters_length =
                binary::hton<uint16_t>(pwd_algo.parameter().size());
            std::ranges::copy(pwd_algo.parameter(),
                              (std::byte *)p->parameters());
            ++sub_it;
        }
        if (sub_it.data() > buf_end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_PASSWORD_ALGORITHMS);
        iter->length = binary::hton<uint16_t>(sub_it.data() - iter->value());
        ++iter;
    }

    if (!this->realm.empty()) {
        if (iter == end)
            goto overflow;
        if (this->realm.size() > 763)
            goto overflow;
        if (iter->value() + this->realm.size() > buf_end)
            goto overflow;
        iter->type = binary::hton<uint16_t>(attr_type_t::STUN_ATTR_REALM);
        iter->length = binary::hton<uint16_t>(this->realm.size());
        std::ranges::copy(this->realm, (char *)iter->value());
        ++iter;
    }

    if (!this->nonce.empty()) {
        if (iter == end)
            goto overflow;
        if (this->nonce.size() > 763)
            goto overflow;
        if (iter->value() + this->nonce.size() > buf_end)
            goto overflow;
        iter->type = binary::hton<uint16_t>(attr_type_t::STUN_ATTR_NONCE);
        iter->length = binary::hton<uint16_t>(this->nonce.size());
        std::ranges::copy(this->nonce, (char *)iter->value());
        ++iter;
    }

    if (this->userhash) {
        if (iter == end)
            goto overflow;
        if (iter->value() + USERHASH_SIZE > buf_end)
            goto overflow;
        iter->type = binary::hton<uint16_t>(attr_type_t::STUN_ATTR_USERHASH);
        iter->length = binary::hton<uint16_t>(USERHASH_SIZE);
        std::ranges::copy(*this->userhash, iter->value());
        ++iter;
    }

    if (this->priority) {
        if (iter == end)
            goto overflow;
        if (iter->value() + 4 > buf_end)
            goto overflow;
        iter->type = binary::hton<uint16_t>(attr_type_t::STUN_ATTR_PRIORITY);
        iter->length = binary::hton<uint16_t>(4);
        binary::write_big<uint16_t>(iter->value(), *this->priority);
        ++iter;
    }

    if (this->use_candidate) {
        if (iter == end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_USE_CANDIDATE);
        iter->length = 0;
        ++iter;
    }

    if (this->ice_controlling) {
        if (iter == end)
            goto overflow;
        if (iter->value() + 8 > buf_end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_ICE_CONTROLLING);
        iter->length = binary::hton<uint16_t>(8);
        binary::write_big<uint64_t>(iter->value(), *this->ice_controlling);
        ++iter;
    }

    if (this->ice_controlled) {
        if (iter == end)
            goto overflow;
        if (iter->value() + 8 > buf_end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_ICE_CONTROLLED);
        iter->length = binary::hton<uint16_t>(8);
        binary::write_big<uint64_t>(iter->value(), *this->ice_controlled);
        ++iter;
    }

    if (this->channel_number) {
        if (iter == end)
            goto overflow;
        if (iter->value() + sizeof(value_channel_number_t) > buf_end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_CHANNEL_NUMBER);
        iter->length = binary::hton<uint16_t>(sizeof(value_channel_number_t));

        auto *cn = reinterpret_cast<value_channel_number_t *>(iter->value());
        cn->channel_number = binary::hton<uint16_t>(*this->channel_number);
        cn->reserved = 0;
        ++iter;
    }

    if (this->lifetime) {
        if (iter == end)
            goto overflow;
        if (iter->value() + 4 > buf_end)
            goto overflow;
        iter->type = binary::hton<uint16_t>(attr_type_t::STUN_ATTR_LIFETIME);
        iter->length = binary::hton<uint16_t>(4);
        binary::write_big<uint32_t>(iter->value(), *this->lifetime);
        ++iter;
    }

    for (const auto &peer : this->xor_peer_address) {
        if (iter == end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_XOR_PEER_ADDRESS);
        auto attr_size = write_xor_address(
            iter->value(), buf_end - iter->value(), header, peer);
        if (attr_size < 0)
            goto overflow;
        iter->length = binary::hton<uint16_t>(static_cast<uint16_t>(attr_size));
        ++iter;
    }

    if (this->xor_relayed_address) {
        if (iter == end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_XOR_RELAYED_ADDRESS);
        auto attr_size =
            write_xor_address(iter->value(), buf_end - iter->value(), header,
                              *this->xor_relayed_address);
        if (attr_size < 0)
            goto overflow;
        iter->length = binary::hton<uint16_t>(static_cast<uint16_t>(attr_size));
        ++iter;
    }

    if (this->even_port) {
        if (iter == end)
            goto overflow;
        if (iter->value() + sizeof(value_even_port_t) > buf_end)
            goto overflow;
        iter->type = binary::hton<uint16_t>(attr_type_t::STUN_ATTR_EVEN_PORT);
        iter->length = binary::hton<uint16_t>(sizeof(value_even_port_t));

        auto *ep = reinterpret_cast<value_even_port_t *>(iter->value());
        // TODO
    }

    if (this->requested_transport) {
        if (iter == end)
            goto overflow;
        if (iter->value() + sizeof(value_requested_transport_t) > buf_end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_REQUESTED_TRANSPORT);
        iter->length =
            binary::hton<uint16_t>(sizeof(value_requested_transport_t));

        auto *rt =
            reinterpret_cast<value_requested_transport_t *>(iter->value());
        rt->protocol = 17;
        rt->reserved1 = 0;
        rt->reserved2 = 0;
        ++iter;
    }

    if (this->dont_fragment) {
        if (iter == end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_DONT_FRAGMENT);
        iter->length = 0;
        ++iter;
    }

    if (this->reservation_token) {
        if (iter == end)
            goto overflow;
        if (iter->value() + 8 > buf_end)
            goto overflow;
        iter->type =
            binary::hton<uint16_t>(attr_type_t::STUN_ATTR_RESERVATION_TOKEN);
        iter->length = binary::hton<uint16_t>(8);
        binary::write_big<uint64_t>(iter->value(), *this->reservation_token);
        ++iter;
    }

    if (iter != end) {
        static constexpr std::string_view sw = "asio-ice";
        if (iter->value() + sw.size() <= buf_end) {
            iter->type =
                binary::hton<uint16_t>(attr_type_t::STUN_ATTR_SOFTWARE);
            iter->length = binary::hton<uint16_t>(sw.size());
            std::ranges::copy(sw, iter->value());
            ++iter;
        }
    }

    for (const auto &algo : integrities) {
        if (iter == end)
            goto overflow;
        uint16_t attr_size;
        switch (algo.algo()) {
        case integrity::SHA1:
            iter->type = binary::hton<uint16_t>(
                attr_type_t::STUN_ATTR_MESSAGE_INTEGRITY);
            attr_size = hash::sha1::digest_size;
            iter->length = binary::hton<uint16_t>(hash::sha1::digest_size);
            break;
        case integrity::SHA256:
            iter->type = binary::hton<uint16_t>(
                attr_type_t::STUN_ATTR_MESSAGE_INTEGRITY_SHA256);
            attr_size = hash::sha256::digest_size;
            iter->length = binary::hton<uint16_t>(hash::sha256::digest_size);
            break;
        default:
            ICE_IN_DEBUG { std::cerr << "Unknown integrity algorithm\n"; }
            continue;
        }
        if (iter->value() + attr_size > buf_end)
            goto overflow;
        header->length = binary::hton<uint16_t>(
            (iter.data() - buf_begin) - sizeof(header_t) + 4 + attr_size);
        if (algo == integrity::SHA1) {
            hash::hmac_context<hash::sha1> ctx(_hmac_key);
            ctx.update(buf_begin, iter.data() - buf_begin);
            ctx.final(iter->value(), attr_size);
        } else {
            hash::hmac_context<hash::sha256> ctx(_hmac_key);
            ctx.update(buf_begin, iter.data() - buf_begin);
            ctx.final(iter->value(), attr_size);
        }

        ++iter;
    }

    if (_use_fingerprint) {
        if (iter == end)
            goto overflow;
        if (iter->value() + 4 > buf_end)
            goto overflow;
        iter->type = binary::hton<uint16_t>(attr_type_t::STUN_ATTR_FINGERPRINT);
        iter->length = binary::hton<uint16_t>(4);

        header->length = binary::hton<uint16_t>((iter.data() - buf_begin) -
                                                sizeof(header_t) + 4 + 4);
        boost::crc_32_type crc;
        crc.process_bytes(buf_begin, iter.data() - buf_begin);
        binary::write_big<uint32_t>(iter->value(), crc.checksum() ^ 0x5354554e);
        ++iter;
    }

    // TODO
    if (iter.data() > buf_end)
        goto overflow;

    binary::write_big<uint16_t>(&header->length,
                                iter.data() - buf_begin - sizeof(header_t));
    return iter.data() - buf_begin;
overflow:
    ICE_IN_DEBUG { std::cerr << "Buffer is too small.\n"; };
    return -1;
}

bool message::is_not_stun(const void *data, std::size_t length) noexcept {
    if (!data || length < sizeof(header_t))
        return true;
    if (*static_cast<const uint8_t *>(data) & 0xC0)
        return true;
    const auto *header = static_cast<const header_t *>(data);
    if (binary::ntoh<uint32_t>(header->magic) != STUN_MAGIC)
        return true;
    const uint16_t len = binary::ntoh<uint16_t>(header->length);
    if (len & 0x3)
        return true;
    if (len + sizeof(header_t) != length)
        return true;
    return false;
}

const uint8_t *
message::get_transaction_id(const void *data,
                            std::size_t length) noexcept(!ICE_DEBUG) {
    ICE_IN_DEBUG {
        if (is_not_stun(data, length))
            throw std::runtime_error{
                "get_transaction_id: is not a stun packet"};
    }
    (void)length;
    return static_cast<const header_t *>(data)->transaction_id;
}

bool message::is_response(const void *data,
                          std::size_t length) noexcept(!ICE_DEBUG) {
    ICE_IN_DEBUG {
        if (is_not_stun(data, length))
            throw std::runtime_error{"is_response: is not a stun packet"};
    }
    (void)length;
    const auto *header = static_cast<const header_t *>(data);
    uint16_t type = binary::ntoh<uint16_t>(header->type);
    uint16_t cls = type & STUN_CLASS_MASK;
    return (cls & 0x0100) != 0;
}

void message::compute_userhash(void *out, std::string_view username,
                               std::string_view realm) {
    std::string input(username);
    input += ':';
    input += realm;
    hash::SHA256(out, input);
}

void message::reset() noexcept {
    cls = 0;
    method = 0;
    transaction_id.fill(0);
    mapped_address.reset();
    xor_mapped_address.reset();
    username.clear();
    integrities.clear();
    pwd_algorithm.reset();
    pwd_algorithms.clear();
    error_code.reset();
    realm.clear();
    nonce.clear();
    software.clear();
    userhash.reset();
    priority.reset();
    ice_controlling.reset();
    ice_controlled.reset();
    use_candidate = false;
    changed_address.reset();
    channel_number.reset();
    lifetime.reset();
    xor_peer_address.clear();
    xor_relayed_address.reset();
    requested_transport = false;
    response_origin.reset();
    other_address.reset();
    alternate_server.reset();
    even_port = false;
    next_port = false;
    dont_fragment = false;
    reservation_token.reset();
    _raw_data.clear();
    _checked_fingerprint = false;
    _hmac_key.clear();
    _use_fingerprint = false;
}

std::size_t message::serialized_size() const noexcept {
    constexpr auto align_size = [](std::size_t size) {
        return (size + 3) & ~3;
    };

    std::size_t total = sizeof(header_t);
    if (this->error_code) {
        total += align_size(4 + sizeof(value_error_code_t) +
                            this->error_code->reason.size());
    }

    if (this->mapped_address) {
        if (this->mapped_address->address.is_v4())
            total += 4 + 4 + 4;
        else
            total += 4 + 4 + 16;
    }

    if (this->xor_mapped_address) {
        if (this->xor_mapped_address->address.is_v4())
            total += 4 + 4 + 4;
        else
            total += 4 + 4 + 16;
    }

    if (!this->username.empty()) {
        total += align_size(4 + this->username.size());
    }

    if (this->pwd_algorithm) {
        total += align_size(4 + sizeof(value_password_algorithm_t) +
                            this->pwd_algorithm->parameter().size());
    }

    if (!this->pwd_algorithms.empty()) {
        total += 4;
        for (const auto &pwd_algo : this->pwd_algorithms) {
            total += align_size(4 + pwd_algo.parameter().size());
        }
    }

    if (!this->realm.empty()) {
        total += align_size(4 + this->realm.size());
    }

    if (!this->nonce.empty()) {
        total += align_size(4 + this->nonce.size());
    }

    if (this->userhash) {
        total += 4 + USERHASH_SIZE;
    }

    if (this->priority) {
        total += 4 + 4;
    }

    if (this->use_candidate) {
        total += 4;
    }

    if (this->ice_controlling) {
        total += 4 + 8;
    }

    if (this->ice_controlled) {
        total += 4 + 8;
    }

    if (this->channel_number) {
        total += align_size(4 + sizeof(value_channel_number_t));
    }

    if (this->lifetime) {
        total += 4 + 4;
    }

    for (const auto &peer : this->xor_peer_address) {
        if (peer.address.is_v4())
            total += 4 + 4 + 4;
        else
            total += 4 + 4 + 16;
    }

    if (this->xor_relayed_address) {
        if (this->xor_relayed_address->address.is_v4())
            total += 4 + 4 + 4;
        else
            total += 4 + 4 + 16;
    }

    if (this->even_port) {
        total += align_size(4 + sizeof(value_even_port_t));
    }

    if (this->requested_transport) {
        total += align_size(4 + sizeof(value_requested_transport_t));
    }

    if (this->dont_fragment) {
        total += 4;
    }

    if (this->reservation_token) {
        total += 4 + 8;
    }

    total += align_size(4 + std::string_view{"asio-ice"}.size());

    for (const auto &algo : integrities) {
        switch (algo.algo()) {
        case integrity::SHA1:
            total += align_size(4 + hash::sha1::digest_size);
            break;
        case integrity::SHA256:
            total += align_size(4 + hash::sha256::digest_size);
            break;
        default:
            continue;
        }
    }

    if (_use_fingerprint) {
        total += 4 + 4;
    }

    return total;
}

void message::fill_random_transaction_id() {
    hash::random_bytes(this->transaction_id.data(),
                       this->transaction_id.size());
}

void message::prepend_nonce_cookie() {
    char cookie[STUN_NONCE_COOKIE.length() + 4 + 1] = {0};
    std::copy_n(STUN_NONCE_COOKIE.begin(), STUN_NONCE_COOKIE.length(), cookie);
    uint32_t features = binary::hton<uint32_t>(_security_features);
    base64::encode(cookie + STUN_NONCE_COOKIE.length(),
                   (uint8_t *)&features + 1, 3);
    this->nonce.insert(0, cookie);
}

static nlohmann::json to_json(const endpoint &ep) {
    nlohmann::json obj;
    obj["family"] = ep.address.is_v4() ? "ipv4" : "ipv6";
    obj["port"] = ep.port;
    obj["address"] = ep.address.to_string();
    return obj;
}

static const char *algo_name(uint16_t algo) noexcept {
    switch (algo) {
    case message::password_algorithm::MD5:
        return "md5";
    case message::password_algorithm::SHA256:
        return "sha256";
    default:
        return "unknown";
    }
}

static const char *algo_name(message::integrity::algo_t algo) noexcept {
    switch (algo) {
    case message::integrity::algo_t::SHA1:
        return "sha1";
    case message::integrity::algo_t::SHA256:
        return "sha256";
    default:
        return "unknown";
    }
}

static nlohmann::json to_json(const message::password_algorithm &pa) noexcept {
    nlohmann::json obj;
    obj["type"] = "password_algorithm";
    obj["algo"] = algo_name(pa.algo());
    const auto &param = pa.parameter();
    if (!param.empty())
        obj["parameter"] = hash::to_hex(param.data(), param.size());
    return obj;
}

std::string message::to_string() {
    nlohmann::json obj;

    obj["class"] = [this] {
        switch (this->cls) {
        case class_t::STUN_CLASS_REQUEST:
            return "request";
        case class_t::STUN_CLASS_INDICATION:
            return "indication";
        case class_t::STUN_CLASS_RESP_SUCCESS:
            return "success_response";
        case class_t::STUN_CLASS_RESP_ERROR:
            return "error_response";
        default:
            return "unknown";
        }
    }();

    obj["method"] = [this] {
        switch (this->method) {
        case method_t::STUN_METHOD_BINDING:
            return "binding";
        case method_t::STUN_METHOD_ALLOCATE:
            return "allocate";
        case method_t::STUN_METHOD_REFRESH:
            return "refresh";
        case method_t::STUN_METHOD_SEND:
            return "send";
        case method_t::STUN_METHOD_DATA:
            return "data";
        case method_t::STUN_METHOD_CREATE_PERMISSION:
            return "create_permission";
        case method_t::STUN_METHOD_CHANNEL_BIND:
            return "channel_bind";
        default:
            return "unknown";
        }
    }();

    obj["transaction_id"] =
        hash::to_hex(transaction_id.data(), transaction_id.size());

    nlohmann::json attributes = nlohmann::json::array();
    if (this->mapped_address) {
        nlohmann::json mapped_address_obj;
        mapped_address_obj["type"] = "mapped_address";
        mapped_address_obj["value"] = to_json(*this->mapped_address);
        attributes.emplace_back(std::move(mapped_address_obj));
    }
    if (this->xor_mapped_address) {
        nlohmann::json xor_mapped_address_obj;
        xor_mapped_address_obj["type"] = "xor_mapped_address";
        xor_mapped_address_obj["value"] = to_json(*this->xor_mapped_address);
        attributes.emplace_back(std::move(xor_mapped_address_obj));
    }
    if (!this->xor_peer_address.empty()) {
        nlohmann::json xor_peer_address_obj;
        xor_peer_address_obj["type"] = "xor_peer_address";
        auto &arr = xor_peer_address_obj["value"];
        for (const auto &peer : this->xor_peer_address)
            arr.push_back(to_json(peer));
        attributes.emplace_back(std::move(xor_peer_address_obj));
    }
    if (this->xor_relayed_address) {
        nlohmann::json xor_relayed_address_obj;
        xor_relayed_address_obj["type"] = "xor_relayed_address";
        xor_relayed_address_obj["value"] = to_json(*this->xor_relayed_address);
        attributes.emplace_back(std::move(xor_relayed_address_obj));
    }
    if (this->changed_address) {
        nlohmann::json changed_address_obj;
        changed_address_obj["type"] = "changed_address";
        changed_address_obj["value"] = to_json(*this->changed_address);
        attributes.emplace_back(std::move(changed_address_obj));
    }
    if (!this->software.empty()) {
        nlohmann::json software_obj;
        software_obj["type"] = "software";
        software_obj["value"] = this->software;
        attributes.emplace_back(std::move(software_obj));
    }
    if (this->priority) {
        nlohmann::json priority_obj;
        priority_obj["type"] = "priority";
        priority_obj["value"] = *this->priority;
        attributes.emplace_back(std::move(priority_obj));
    }
    if (!this->username.empty()) {
        nlohmann::json username_obj;
        username_obj["type"] = "username";
        username_obj["value"] = this->username;
        attributes.emplace_back(std::move(username_obj));
    }
    if (this->ice_controlling) {
        nlohmann::json ice_controlling_obj;
        ice_controlling_obj["type"] = "ice_controlling";
        ice_controlling_obj["value"] = *this->ice_controlling;
        attributes.emplace_back(std::move(ice_controlling_obj));
    }
    if (this->use_candidate) {
        nlohmann::json use_candidate_obj;
        use_candidate_obj["type"] = "use_candidate";
        attributes.emplace_back(std::move(use_candidate_obj));
    }
    if (this->ice_controlled) {
        nlohmann::json ice_controlled_obj;
        ice_controlled_obj["type"] = "ice_controlled";
        ice_controlled_obj["value"] = *this->ice_controlled;
        attributes.emplace_back(std::move(ice_controlled_obj));
    }
    if (this->error_code) {
        nlohmann::json error_code_obj;
        error_code_obj["type"] = "error_code";
        nlohmann::json ec;
        ec["code"] = this->error_code->code;
        ec["reason"] = this->error_code->reason;
        error_code_obj["value"] = std::move(ec);
        attributes.emplace_back(std::move(error_code_obj));
    }
    if (!this->realm.empty()) {
        nlohmann::json realm_obj;
        realm_obj["type"] = "realm";
        realm_obj["value"] = this->realm;
        attributes.emplace_back(std::move(realm_obj));
    }
    if (!this->nonce.empty()) {
        nlohmann::json nonce_obj;
        nonce_obj["type"] = "nonce";
        nonce_obj["value"] = this->nonce;
        attributes.emplace_back(std::move(nonce_obj));
    }
    if (this->pwd_algorithm) {
        attributes.emplace_back(to_json(*this->pwd_algorithm));
    }
    if (!this->pwd_algorithms.empty()) {
        nlohmann::json pwd_algos_obj;
        pwd_algos_obj["type"] = "password_algorithms";
        nlohmann::json algos = nlohmann::json::array();
        for (const auto &pwd_algo : this->pwd_algorithms) {
            algos.emplace_back(to_json(pwd_algo));
        }
        pwd_algos_obj["value"] = std::move(algos);
        attributes.emplace_back(std::move(pwd_algos_obj));
    }
    if (this->userhash) {
        nlohmann::json userhash_obj;
        userhash_obj["type"] = "userhash";
        userhash_obj["value"] =
            hash::to_hex(this->userhash->data(), USERHASH_SIZE);
        attributes.emplace_back(std::move(userhash_obj));
    }
    if (this->channel_number) {
        nlohmann::json channel_num_obj;
        channel_num_obj["type"] = "channel_number";
        channel_num_obj["value"] = *this->channel_number;
        attributes.emplace_back(std::move(channel_num_obj));
    }
    if (this->lifetime) {
        nlohmann::json lifetime_obj;
        lifetime_obj["type"] = "lifetime";
        lifetime_obj["value"] = *this->lifetime;
        attributes.emplace_back(std::move(lifetime_obj));
    }
    if (this->even_port) {
        nlohmann::json even_port_obj;
        even_port_obj["type"] = "even_port";
        even_port_obj["vaLue"] = this->even_port;
        attributes.emplace_back(std::move(even_port_obj));
    }
    if (this->requested_transport) {
        nlohmann::json requested_transport_obj;
        requested_transport_obj["type"] = "requested_transport";
        attributes.emplace_back(std::move(requested_transport_obj));
    }
    if (this->dont_fragment) {
        nlohmann::json dont_fragment_obj;
        dont_fragment_obj["type"] = "dont_fragment";
        attributes.emplace_back(std::move(dont_fragment_obj));
    }
    if (this->reservation_token) {
        nlohmann::json reservation_token_obj;
        reservation_token_obj["type"] = "reservation_token";
        reservation_token_obj["value"] = *this->reservation_token;
    }
    for (const auto &integrity : this->integrities) {
        nlohmann::json integrity_obj;
        integrity_obj["type"] =
            std::string{"integrity_"} + algo_name(integrity.algo());
        if (!this->_raw_data.empty() &&
            !is_not_stun(this->_raw_data.data(), this->_raw_data.size())) {
            const attr_t *attr = find_attr(
                this->_raw_data.data(), this->_raw_data.size(),
                integrity.algo() == integrity::algo_t::SHA1
                    ? attr_type_t::STUN_ATTR_MESSAGE_INTEGRITY
                    : attr_type_t::STUN_ATTR_MESSAGE_INTEGRITY_SHA256);
            if (!attr || (const std::byte *)attr + 4 +
                                 binary::ntoh<uint16_t>(attr->length) >
                             this->_raw_data.data() + this->_raw_data.size()) {
                attributes.emplace_back(std::move(integrity_obj));
                continue;
            }
            integrity_obj["value"] = hash::to_hex(
                attr->value(), binary::ntoh<uint16_t>(attr->length));
        }
        attributes.emplace_back(std::move(integrity_obj));
    }
    if (this->_checked_fingerprint) {
        nlohmann::json fingerprint_obj;
        fingerprint_obj["type"] = "fingerprint";
        attributes.emplace_back(std::move(fingerprint_obj));
    }
    obj["attributes"] = std::move(attributes);

    return obj.dump(2);
}

} // namespace ice::stun