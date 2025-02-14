#pragma once

#include "endian.hpp"

#include "json.hpp"

#include <vector>
#include <memory>
#include <string>
#include <array>
#include <cstddef>
#include <variant>
#include <optional>
#include <expected>

namespace mdns::dns {

enum struct op_code: uint16_t{
	OKAY = 0, /* RFC-1035 */
	FORMAT_ERROR = 1, /* RFC-1035 */
	SERVER_FAILURE = 2, /* RFC-1035 */
	NAME_ERROR = 3, /* RFC-1035 */
	NOT_IMPLEMENTED = 4, /* RFC-1035 */
	REFUSED = 5, /* RFC-1035 */
	YXDOMAIN = 6, /* RFC-2136 */
	YXRRSET = 7, /* RFC-2136 */
	NXRRSET = 8, /* RFC-2136 */
	NOTAUTH = 9, /* RFC-2136 */
	NOTZONE = 10, /* RFC-2136 */
	BADVERS = 16, /* RFC-2671 */
	BADSIG = 16, /* RFC-2845 */
	BADKEY = 17, /* RFC-2845 */
	BADTIME = 18, /* RFC-2845 */
	BADMODE = 19, /* RFC-2845 */
	BADNAME = 20, /* RFC-2930 */
	BADALG = 21, /* RFC-2930 */
	BADTRUC = 22, /* RFC-4635 */
	PRIVATE = 3841, /* RFC-2929 */
};

namespace rdata{
    using a = uint32_t;
    using aaaa = std::array<unsigned char, 16>;
    struct cname: public std::string{};
    struct hinfo{
        std::string cpu;
        std::string os;
    };
    struct mx{
        int16_t preference{ 0 };
        std::string exchange;
    };
    struct ns: public std::string{};
    struct ptr: public std::string{};
    struct soa{
        std::string mname;
        std::string rname;
        uint32_t serial{ 0 };
        int32_t refresh{ 0 };
        int32_t retry{ 0 };
        int32_t expire{ 0 };
        uint32_t minimum{ 0 };
    };
    struct txt: public std::string{};
    struct wks{
        uint32_t address{ 0 };
        uint8_t protocol{ 0 };
        std::vector<bool> bitmap;
    };
    struct srv{
        uint16_t priority{ 0 };
        uint16_t weight{ 0 };
        uint16_t port{ 0 };
        std::string target;
    };
} // namespace rdata

using generic_rdata_t = std::variant<
    std::monostate,
    rdata::a,
    rdata::aaaa,
    rdata::cname,
    rdata::hinfo,
    rdata::mx,
    rdata::ns,
    rdata::ptr,
    rdata::soa,
    rdata::txt,
    rdata::wks,
    rdata::srv
>;

struct record_type {
    static constexpr uint16_t A = 1;
    static constexpr uint16_t NS = 2;
    static constexpr uint16_t CNAME = 5;
    static constexpr uint16_t SOA = 6;
    static constexpr uint16_t WKS = 11;
    static constexpr uint16_t PTR = 12;
    static constexpr uint16_t HINFO = 13;
    static constexpr uint16_t MX = 15;
    static constexpr uint16_t TXT = 16;
    static constexpr uint16_t AAAA = 28;
    static constexpr uint16_t SRV = 33;
    static constexpr uint16_t ANY = 255;
    static constexpr uint16_t UknownType = 65280;

    record_type(uint16_t value = 0) : _value(value) {}
    operator uint16_t() const noexcept { return _value; }
    operator uint16_t&() noexcept { return _value; }
private:
    uint16_t _value;
};

record_type get_record_type(const generic_rdata_t& data)noexcept;

struct record_class {
    static constexpr uint16_t INTERNET = 1; /* Internet	    	RFC-1035 */
    static constexpr uint16_t CSNET = 2; /* CSNET (obsolete)    	RFC-1035 */
    static constexpr uint16_t CHAOS = 3; /* CHAOS		RFC-1035 */
    static constexpr uint16_t HESIOD = 4; /* Hesiod		RFC-1035 */
    static constexpr uint16_t NONE = 254; /* 			RFC-2136 */
    static constexpr uint16_t ANY = 255; /* All classes		RFC-1035 */
    static constexpr uint16_t UknownClass = 65280; /* Unknown class 	RFC-2929 */

    record_class(uint16_t value = 0) : _value(value) {}
    operator uint16_t() const noexcept { return _value; }
    operator uint16_t&() noexcept { return _value; }
private:
    uint16_t _value;
};

struct question_t{
    std::string name;
    record_type type;
    record_class cls;

    bool is_unicast()const noexcept {
        return (cls & (uint16_t{1} << 15)) != 0;
    }

    nlohmann::json to_json()const;
};

struct record_t{
    std::string name;
    record_class cls;
    int32_t ttl{ 0 };
    uint16_t rdlength{ 0 };
    generic_rdata_t data;

    record_type type()const noexcept{
        return get_record_type(data);
    }

    bool is_unicast()const noexcept {
        return (cls & (uint16_t{ 1 } << 15)) != 0;
    }

    nlohmann::json to_json()const;
};

struct message_t{
    #pragma pack(push, 1)
    struct header_t{
        uint16_t id{ 0 };

        struct flags_t{
        #ifdef __MDNS_LITTLE_ENDIAN__
            uint8_t rd:1{ 0 };
            uint8_t tc:1{ 0 };
            uint8_t aa:1{ 0 };
            uint8_t opcode:4{ 0 };
            uint8_t qr:1{ 0 };

            uint8_t rcode:4{ 0 };
            uint8_t z:3{ 0 };
            uint8_t ra:1{ 0 };
        #else
            uint8_t qr:1{ 0 };
            uint8_t opcode:4{ 0 };
            uint8_t aa:1{ 0 };
            uint8_t tc:1{ 0 };
            uint8_t rd:1{ 0 };

            uint8_t ra:1{ 0 };
            uint8_t z:3{ 0 };
            uint8_t rcode:4{ 0 };
        #endif
        };
        flags_t flags;

        uint16_t questions_count{ 0 };
        uint16_t answers_count{ 0 };
        uint16_t authorities_count{ 0 };
        uint16_t additionals_count{ 0 };

        nlohmann::json to_json()const;
    };
    #pragma pack(pop)
    static_assert(sizeof(header_t) == 12);

    bool is_response()const noexcept;
    bool is_query()const noexcept;
    static std::expected<message_t, std::error_code> parse(const void* buf, std::size_t size);
    std::expected<std::size_t, std::error_code> write(void* buf, std::size_t size);
    static bool possible_valid(const void* buf, std::size_t size)noexcept;

    header_t header;
    std::vector<question_t> questions;
    std::vector<record_t> answers;
    std::vector<record_t> authorities;
    std::vector<record_t> additionals;

    nlohmann::json to_json()const;    
};

} // namespace mdns::dns