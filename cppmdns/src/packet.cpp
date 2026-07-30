#include "packet.hpp"
#include "binary.hpp"
#include "error.hpp"
#include "config.hpp"
#include "split.hpp"
#include "samlog.hpp"

#if CPPMDNS_USE_BOOST_ASIO > 0
#include <boost/asio/ip/address.hpp>
namespace mdns {
namespace net = boost::asio;
}
#else
#include <asio/ip/address.hpp>
namespace mdns {
namespace net = asio;
}
#endif // CPPMDNS_USE_BOOST_ASIO

#include "json.hpp"

#include <cstring>
#include <cassert>
#include <string_view>
#include <ranges>
#include <locale>
#include <algorithm>

namespace mdns::dns {

static bool __is_valid_domain_name(std::string_view name) noexcept {
    return true;
    if (name.empty())
        return false;
    if (name == ".")
        return true;
    if (name.size() > 255)
        return false;
    if (std::any_of(name.begin(), name.end(), [](char c) {
            return !std::isdigit(c) && !std::isalpha(c) && c != '-' &&
                   c != '.' && c != '_';
        }))
        return false;
    if (name.front() == '-' || name.back() == '-')
        return false;
    if (name.front() == '.')
        return false;
    if (name.back() == '.')
        name.remove_suffix(1);
    auto splited = utils::split(name, '.');
    if (std::any_of(splited.begin(), splited.end(), [](auto &&sv) {
            return sv.empty() || sv.front() == '-' || sv.back() == '-';
        })) {
        return false;
    }
    return true;
}

static std::error_code __parse_name(std::string &name, const void *buf,
                                    std::size_t size, std::size_t &offset,
                                    int depth) {
    if (depth > 20)
        return std::error_code{(int)error::invalid_format, mdns_category()};
    if (offset >= size)
        return std::error_code{(int)error::out_of_range, mdns_category()};
    const char *iter = (const char *)buf + offset;
    const char *const end = (const char *)buf + size;
    while (iter < end) {
        const uint8_t len = binary::read_big<uint8_t>(iter);
        if (len == 0) {
            if (name.empty())
                name += '.';
            else {
                if (name.back() == '.') {
                    assert(name.size() > 1);
                    name.pop_back();
                }
                if (!__is_valid_domain_name(name)) {
                    SAMLOG_DEBUG(auto sink) {
                        char buf[256];
                        sink({buf, sizeof(buf)}, "invalid domain name: {}\n",
                             name);
                    };
                    return std::error_code{(int)error::invalid_domain_name,
                                           mdns_category()};
                }
            }
            offset = iter - (const char *)buf + 1;
            return {};
        }
        if ((len & 0b11000000) == 0b11000000) {
            // pointer
            if (iter + 1 >= end)
                return std::error_code{(int)error::out_of_range,
                                       mdns_category()};
            const uint16_t ptr = binary::read_big<uint16_t>(iter) - 0xC000;
            if (ptr >= offset) {
                SAMLOG_DEBUG(auto sink) {
                    char buf[256];
                    sink({buf, sizeof(buf)}, "invalid pointer: {} >= {}\n", ptr,
                         offset);
                };
                return std::error_code{(int)error::invalid_format,
                                       mdns_category()};
            }
            std::size_t ptr_offset = ptr;
            const auto ec =
                __parse_name(name, buf, offset, ptr_offset, depth + 1);
            offset = iter - (const char *)buf + 2;
            return ec;
        } else if ((len & 0b11000000) == 0) {
            // label
            if (iter + len + 1 > end)
                return std::error_code{(int)error::out_of_range,
                                       mdns_category()};
            const std::string_view label{iter + 1, len};
            name += label;
            name += '.';
            iter += len + 1;
        } else {
            return std::error_code{(int)error::invalid_format, mdns_category()};
        }
        if (name.size() > 255)
            return std::error_code{(int)error::invalid_format, mdns_category()};
    }
    return std::error_code{(int)error::invalid_format, mdns_category()};
}

static void __parse_a(rdata::a &data, const void *ptr) noexcept {
    data = binary::read_big<uint32_t>(ptr);
}

static void __parse_aaaa(rdata::aaaa &data, const void *ptr) noexcept {
    std::copy_n((const uint8_t *)ptr, 16, data.data());
}

static std::error_code __parse_cname(rdata::cname &data, const void *buf,
                                     const void *ptr, std::size_t rdlength) {
    // TODO: verify canonical name
    std::size_t offset = (const char *)ptr - (const char *)buf;
    const auto ec = __parse_name(data, buf, offset + rdlength, offset, 1);
    if (offset != (const char *)ptr - (const char *)buf + rdlength)
        return std::error_code{(int)error::invalid_format, mdns_category()};
    return ec;
}

static void __parse_hinfo(rdata::hinfo &data, const void *buf, const void *ptr,
                          std::size_t rdlength) {
    // TODO
}

static void __write_hinfo(const rdata::hinfo &data, void *ptr,
                          std::size_t rdlength) noexcept {
    // TODO
}

static std::error_code __parse_mx(rdata::mx &data, const void *buf,
                                  const void *ptr, std::size_t rdlength) {
    data.preference = binary::read_big<int16_t>(ptr);
    std::size_t offset = (const char *)ptr - (const char *)buf + 2;
    const auto ec = __parse_name(
        data.exchange, buf, (const char *)ptr - (const char *)buf + rdlength,
        offset, 1);
    if (offset != (const char *)ptr - (const char *)buf + rdlength)
        return std::error_code{(int)error::invalid_format, mdns_category()};
    return ec;
}

static std::error_code __parse_ns(rdata::ns &data, const void *buf,
                                  const void *ptr, std::size_t rdlength) {
    std::size_t offset = (const char *)ptr - (const char *)buf;
    const auto ec = __parse_name(data, buf, offset + rdlength, offset, 1);
    if (offset != (const char *)ptr - (const char *)buf + rdlength)
        return std::error_code{(int)error::invalid_format, mdns_category()};
    return ec;
}

static std::error_code __parse_ptr(rdata::ptr &data, const void *buf,
                                   const void *ptr, std::size_t rdlength) {
    std::size_t offset = (const char *)ptr - (const char *)buf;
    const auto ec = __parse_name(data, buf, offset + rdlength, offset, 1);
    if (offset != (const char *)ptr - (const char *)buf + rdlength)
        return std::error_code{(int)error::invalid_format, mdns_category()};
    return ec;
}

static std::error_code __parse_soa(rdata::soa &data, const void *buf,
                                   const void *ptr, std::size_t rdlength) {
    const std::size_t size = (const char *)ptr - (const char *)buf + rdlength;
    std::size_t offset = (const char *)ptr - (const char *)buf;
    auto ec = __parse_name(data.mname, buf, size, offset, 1);
    if (ec)
        return ec;
    ec = __parse_name(data.rname, buf, size, offset, 1);
    if (ec)
        return ec;
    offset += binary::unpack<"!L3lL">((const char *)buf + offset, size - offset,
                                      ec, data.serial, data.refresh, data.retry,
                                      data.expire, data.minimum);
    if (offset != size)
        return std::error_code{(int)error::invalid_format, mdns_category()};
    return ec;
}

static void __parse_txt(rdata::txt &data, const void *ptr,
                        std::size_t rdlength) {
    data.assign(std::string_view((const char *)ptr, rdlength));
}

static std::error_code __parse_wks(rdata::wks &data, const void *buf,
                                   const void *ptr, std::size_t rdlength) {
    std::error_code ec;
    binary::unpack<"!LB">(ptr, rdlength, ec, data.address, data.protocol);
    if (ec)
        return ec;
    // TODO: parse bitmap
    return ec;
}

static std::error_code __parse_srv(rdata::srv &data, const void *buf,
                                   const void *ptr, std::size_t rdlength) {
    if (rdlength <= 6)
        return std::error_code{(int)error::invalid_format, mdns_category()};
    std::error_code ec;
    binary::unpack<"!3H">(ptr, rdlength, ec, data.priority, data.weight,
                          data.port);
    if (ec)
        return ec;
    std::size_t offset = (const char *)ptr - (const char *)buf + 6;
    const std::size_t size = (const char *)ptr - (const char *)buf + rdlength;
    return __parse_name(data.target, buf, size, offset, 1);
}

static std::error_code __parse_record(record_t &record, const void *buf,
                                      std::size_t size, std::size_t &offset) {
    auto ec = __parse_name(record.name, buf, size, offset, 1);
    if (ec)
        return ec;
    uint16_t type;
    offset += binary::unpack<"!HHlH">((const char *)buf + offset, size - offset,
                                      ec, type, (uint16_t &)record.cls,
                                      record.ttl, record.rdlength);
    if (ec)
        return ec;
    if (offset + record.rdlength > size)
        return std::error_code{(int)error::out_of_range, mdns_category()};
    const auto data_ptr = (const char *)buf + offset;
    switch ((record_type)type) {
    case record_type::A: {
        if (record.rdlength != 4)
            return std::error_code{(int)error::invalid_format, mdns_category()};
        __parse_a(record.data.emplace<rdata::a>(), data_ptr);
        break;
    }
    case record_type::NS: {
        ec = __parse_ns(record.data.emplace<rdata::ns>(), buf, data_ptr,
                        record.rdlength);
        break;
    }
    case record_type::CNAME: {
        ec = __parse_cname(record.data.emplace<rdata::cname>(), buf, data_ptr,
                           record.rdlength);
        break;
    }
    case record_type::SOA: {
        ec = __parse_soa(record.data.emplace<rdata::soa>(), buf, data_ptr,
                         record.rdlength);
        break;
    }
    case record_type::WKS: {
        ec = __parse_wks(record.data.emplace<rdata::wks>(), buf, data_ptr,
                         record.rdlength);
        break;
    }
    case record_type::PTR: {
        ec = __parse_ptr(record.data.emplace<rdata::ptr>(), buf, data_ptr,
                         record.rdlength);
        break;
    }
    case record_type::HINFO: {
        __parse_hinfo(record.data.emplace<rdata::hinfo>(), buf, data_ptr,
                      record.rdlength);
        break;
    }
    case record_type::MX: {
        ec = __parse_mx(record.data.emplace<rdata::mx>(), buf, data_ptr,
                        record.rdlength);
        break;
    }
    case record_type::TXT: {
        __parse_txt(record.data.emplace<rdata::txt>(), data_ptr,
                    record.rdlength);
        break;
    }
    case record_type::AAAA: {
        if (record.rdlength != 16)
            return std::error_code{(int)error::invalid_format, mdns_category()};
        __parse_aaaa(record.data.emplace<rdata::aaaa>(), data_ptr);
        break;
    }
    case record_type::SRV: {
        ec = __parse_srv(record.data.emplace<rdata::srv>(), buf, data_ptr,
                         record.rdlength);
        break;
    }
    case record_type::UknownType:
    default: {
        SAMLOG_DEBUG(auto sink) {
            char buf[256];
            sink({buf, sizeof(buf)}, "Parse record Unknown record type: {}\n",
                 (uint16_t)record.type());
        };
    }
    }
    if (ec)
        return ec;
    offset += record.rdlength;
    return {};
}

std::expected<message_t, std::error_code> message_t::parse(const void *buf,
                                                           std::size_t size) {
    if (size < 12)
        return std::unexpected(
            std::error_code{(int)error::out_of_range, mdns_category()});
    message_t msg;
    std::error_code ec;
    binary::unpack<"!H2x4H">(
        buf, size, ec, msg.header.id, msg.header.questions_count,
        msg.header.answers_count, msg.header.authorities_count,
        msg.header.additionals_count);
    if (ec) {
        return std::unexpected(ec);
    }
    msg.header.flags =
        std::bit_cast<header_t::flags_t>(((const uint16_t *)buf)[1]);

    const char *const begin = (const char *)buf;
    const char *const end = begin + size;
    std::size_t offset = 12;

    // questions
    if (msg.header.questions_count > 0) {
        msg.questions.resize(msg.header.questions_count);
        for (std::size_t i = 0; i < msg.header.questions_count; ++i) {
            auto &question = msg.questions[i];
            auto ec = __parse_name(question.name, buf, size, offset, 1);
            if (ec)
                return std::unexpected(ec);
            offset += binary::unpack<"!HH">(begin + offset, size - offset, ec,
                                            (uint16_t &)question.type,
                                            (uint16_t &)question.cls);
            if (ec) {
                return std::unexpected(ec);
            }
        }
    }

    // answers
    if (msg.header.answers_count > 0) {
        msg.answers.resize(msg.header.answers_count);
        for (std::size_t i = 0; i < msg.header.answers_count; ++i) {
            auto ec = __parse_record(msg.answers[i], buf, size, offset);
            if (ec)
                return std::unexpected(ec);
        }
    }

    // authorities
    if (msg.header.authorities_count > 0) {
        msg.authorities.resize(msg.header.authorities_count);
        for (std::size_t i = 0; i < msg.header.authorities_count; ++i) {
            auto ec = __parse_record(msg.authorities[i], buf, size, offset);
            if (ec)
                return std::unexpected(ec);
        }
    }

    // additionals
    if (msg.header.additionals_count > 0) {
        msg.additionals.resize(msg.header.additionals_count);
        for (std::size_t i = 0; i < msg.header.additionals_count; ++i) {
            auto ec = __parse_record(msg.additionals[i], buf, size, offset);
            if (ec)
                return std::unexpected(ec);
        }
    }

    return msg;
}

static bool __is_valid_record(const record_t &record) noexcept {
    if (!__is_valid_domain_name(record.name))
        return false;
    switch (record.type()) {
    case record_type::A:
    case record_type::AAAA:
    case record_type::WKS:
        return true;
    case record_type::NS: {
        return __is_valid_domain_name(std::get<rdata::ns>(record.data));
    }
    case record_type::CNAME: {
        return __is_valid_domain_name(std::get<rdata::cname>(record.data));
    }
    case record_type::SOA: {
        const auto &soa = std::get<rdata::soa>(record.data);
        return __is_valid_domain_name(soa.mname) &&
               __is_valid_domain_name(soa.rname);
    }
    case record_type::PTR: {
        return __is_valid_domain_name(std::get<rdata::ptr>(record.data));
    }
    case record_type::HINFO: {
        // TODO:
        return true;
    }
    case record_type::MX: {
        return __is_valid_domain_name(
            std::get<rdata::mx>(record.data).exchange);
    }
    case record_type::TXT: {
        return true;
    }
    case record_type::SRV: {
        return __is_valid_domain_name(std::get<rdata::srv>(record.data).target);
    }
    case record_type::UknownType:
    default: {
        SAMLOG_DEBUG(auto sink) {
            char buf[256];
            sink({buf, sizeof(buf)},
                 "__is_valid_record Unknown record type: {}\n",
                 (uint16_t)record.type());
        };
        return false;
    }
    }
}

static std::error_code __verify_message(const message_t &msg) {
    if (!msg.questions.empty() &&
        std::ranges::any_of(msg.questions, [](const auto &question) {
            return !__is_valid_domain_name(question.name);
        }))
        return std::error_code{(int)error::invalid_domain_name,
                               mdns_category()};
    if (!msg.answers.empty() &&
        std::ranges::any_of(msg.answers, std::not_fn(__is_valid_record)))
        return std::error_code{(int)error::invalid_domain_name,
                               mdns_category()};
    if (!msg.authorities.empty() &&
        std::ranges::any_of(msg.authorities, std::not_fn(__is_valid_record)))
        return std::error_code{(int)error::invalid_domain_name,
                               mdns_category()};
    if (!msg.additionals.empty() &&
        std::ranges::any_of(msg.additionals, std::not_fn(__is_valid_record)))
        return std::error_code{(int)error::invalid_domain_name,
                               mdns_category()};
    return {};
}

class name_compressor {
    static constexpr auto __compare = [](const auto &x,
                                         const auto &y) noexcept {
        return std::ranges::lexicographical_compare(std::views::reverse(x),
                                                    std::views::reverse(y));
    };

    static auto __split(const std::string_view &domain_name) noexcept {
        return std::views::split(domain_name, '.') |
               std::views::transform([](const auto &r) noexcept {
                   return std::string_view{r.begin(), r.end()};
               });
    }

  public:
    void reserve(std::size_t n) { _name_pool.reserve(n); }

    void prepare(const std::string_view &domain_name) {
        std::vector<std::string_view> labels;
        labels.reserve(8);
        auto splited = __split(domain_name);
        std::ranges::copy(splited, std::back_inserter(labels));
        _name_pool.emplace_back(std::move(labels));
    }

    void finally() noexcept {
        if (_name_pool.empty())
            return;
        std::ranges::sort(_name_pool, __compare);
        _name_pool.erase(std::unique(_name_pool.begin(), _name_pool.end()),
                         _name_pool.end());
        _name_offset.resize(_name_pool.size(), -1);
        _tmp.reserve(_name_pool.back().size());
    }

    bool write_name(void *buf, std::size_t size, const std::string_view &name,
                    std::size_t &offset) noexcept {
        if (offset > size || _name_pool.empty())
            return false;
        _tmp.clear();
        std::ranges::copy(__split(name), std::back_inserter(_tmp));
        const auto &labels = _tmp;
        const auto name_pool_begin = _name_pool.begin();
        auto name_pool_end = _name_pool.end();
        const auto offset_tmp{offset};
        const auto it_tmp =
            std::ranges::lower_bound(_name_pool, labels, __compare);
        SAMLOG_DEBUG(auto sink) {
            assert(it_tmp != _name_pool.end() &&
                       std::ranges::equal(labels, *it_tmp) &&
                       "Domain name should be prepared before writing." ||
                   [&]() {
                       char buf[256];
                       sink({buf, sizeof(buf)},
                            "Name \"{}\" is not found in name pool.\n", name);
                       return false;
                   }());
        };
        for (auto label_begin = labels.begin(); label_begin != labels.end();
             ++label_begin) {
            auto it = std::lower_bound(
                name_pool_begin, name_pool_end,
                std::ranges::subrange{label_begin, labels.end()}, __compare);
            if (it == name_pool_end) {
                // write a label
                if (!__write_label(buf, size, *label_begin, offset))
                    return false;
                continue;
            }
            if (std::ranges::equal(
                    *it, std::ranges::subrange{label_begin, labels.end()})) {
                const auto idx = std::distance(name_pool_begin, it);
                if (_name_offset[idx] == -1) {
                    // write a label
                    if (!__write_label(buf, size, *label_begin, offset))
                        return false;
                    name_pool_end = it;
                    continue;
                }
                // write a pointer
                if (!__write_pointer(buf, size, (uint16_t)_name_offset[idx],
                                     offset))
                    return false;
                _name_offset[std::distance(_name_pool.begin(), it_tmp)] =
                    offset_tmp;
                return true;
            }
            // write a label
            if (!__write_label(buf, size, *label_begin, offset))
                return false;
            name_pool_end = it;
        }
        // write 0
        if (offset + 1 > size)
            return false;
        _name_offset[std::distance(_name_pool.begin(), it_tmp)] =
            (int)offset_tmp;
        *((uint8_t *)buf + offset) = 0;
        ++offset;
        return true;
    }

  private:
    static bool __write_label(void *buf, std::size_t size,
                              const std::string_view &label,
                              std::size_t &offset) noexcept {
        if (offset + label.size() + 1 > size)
            return false;
        auto *ptr = (uint8_t *)buf + offset;
        ptr[0] = (uint8_t)label.size();
        std::copy(label.begin(), label.end(), ptr + 1);
        offset += 1 + label.size();
        return true;
    }

    static bool __write_pointer(void *buf, std::size_t size, uint16_t pointer,
                                std::size_t &offset) noexcept {
        if (offset + 2 > size)
            return false;
        assert(pointer < offset);
        auto *ptr = (uint8_t *)buf + offset;
        binary::write_big<uint16_t>(ptr, pointer);
        *ptr |= 0b11000000;
        offset += 2;
        return true;
    }

    std::vector<std::vector<std::string_view>> _name_pool;
    std::vector<int> _name_offset;
    mutable std::vector<std::string_view> _tmp;
};

static void __add_rdata_to_string_pool(name_compressor &pool,
                                       const record_t &record) {
    switch (record.type()) {
    case record_type::NS: {
        const auto &ns = std::get<rdata::ns>(record.data);
        pool.prepare(ns);
        return;
    }
    case record_type::CNAME: {
        const auto &cname = std::get<rdata::cname>(record.data);
        pool.prepare(cname);
        return;
    }
    case record_type::SOA: {
        const auto &soa = std::get<rdata::soa>(record.data);
        pool.prepare(soa.mname);
        pool.prepare(soa.rname);
        return;
    }
    case record_type::PTR: {
        const auto &ptr = std::get<rdata::ptr>(record.data);
        pool.prepare(ptr);
        return;
    }
    case record_type::MX: {
        const auto &mx = std::get<rdata::mx>(record.data);
        pool.prepare(mx.exchange);
        return;
    }
    default:
        return;
    }
}

static void __add_record_to_string_pool(name_compressor &pool,
                                        const record_t &record) {
    pool.prepare(record.name);
    __add_rdata_to_string_pool(pool, record);
}

static std::error_code __write_header(void *buf, std::size_t size,
                                      const message_t &msg) noexcept {
    if (size < 12)
        return std::error_code{(int)error::out_of_range, mdns_category()};
    std::error_code ec;
    binary::pack<"!H2x4H">(buf, size, ec, msg.header.id,
                           msg.header.questions_count, msg.header.answers_count,
                           msg.header.authorities_count,
                           msg.header.additionals_count);
    ((uint16_t *)buf)[1] = std::bit_cast<uint16_t>(msg.header.flags);
    return ec;
}

static void __sort_questions(std::vector<question_t> &questions) noexcept {
    std::sort(questions.begin(), questions.end(),
              [](const question_t &a, const question_t &b) noexcept {
                  return std::ranges::lexicographical_compare(
                      std::views::reverse(a.name), std::views::reverse(b.name));
              });
}

static std::string_view __get_rdata_string(const record_t &record) noexcept {
    switch (record.type()) {
    case record_type::NS: {
        return std::get<rdata::ns>(record.data);
    }
    case record_type::CNAME: {
        return std::get<rdata::cname>(record.data);
    }
    case record_type::SOA: {
        return std::get<rdata::soa>(record.data).mname;
    }
    case record_type::PTR: {
        return std::get<rdata::ptr>(record.data);
    }
    case record_type::MX: {
        return std::get<rdata::mx>(record.data).exchange;
    }
    default:
        return "";
    }
}

static void __sort_records(std::vector<record_t> &records) {
    std::ranges::sort(records,
                      [](const record_t &a, const record_t &b) noexcept {
                          return std::ranges::lexicographical_compare(
                              std::views::reverse(__get_rdata_string(a)),
                              std::views::reverse(__get_rdata_string(b)));
                      });
    std::ranges::stable_sort(
        records, [](const record_t &a, const record_t &b) noexcept {
            return std::ranges::lexicographical_compare(
                std::views::reverse(a.name), std::views::reverse(b.name));
        });
}

static void __write_a(const rdata::a &data, void *ptr) noexcept {
    binary::write_big<uint32_t>(ptr, data);
}

static void __write_aaaa(const rdata::aaaa &data, void *ptr) noexcept {
    std::copy(data.begin(), data.end(), (char *)ptr);
}

static std::error_code __write_record(void *buf, std::size_t size,
                                      const record_t &record,
                                      std::size_t &offset,
                                      name_compressor &compressor) noexcept {
    if (!compressor.write_name(buf, size, record.name, offset))
        return std::error_code{(int)error::out_of_range, mdns_category()};
    if (offset + 10 > size)
        return std::error_code{(int)error::out_of_range, mdns_category()};
    std::error_code ec;
    offset += binary::pack<"!HHl2x">((char *)buf + offset, size - offset, ec,
                                     (uint16_t)record.type(),
                                     (uint16_t)record.cls, record.ttl);
    if (ec)
        return ec;
    const auto rdata_offset = offset;
    char *const begin = (char *)buf;
    switch (record.type()) {
    case record_type::A: {
        if (rdata_offset + 4 > size)
            return std::error_code{(int)error::out_of_range, mdns_category()};
        __write_a(std::get<rdata::a>(record.data), begin + rdata_offset);
        offset += 4;
        break;
    }
    case record_type::NS: {
        if (!compressor.write_name(buf, size, std::get<rdata::ns>(record.data),
                                   offset))
            return std::error_code{(int)error::out_of_range, mdns_category()};
        break;
    }
    case record_type::CNAME: {
        if (!compressor.write_name(buf, size,
                                   std::get<rdata::cname>(record.data), offset))
            return std::error_code{(int)error::out_of_range, mdns_category()};
        break;
    }
    case record_type::SOA: {
        const auto &soa = std::get<rdata::soa>(record.data);
        if (!compressor.write_name(buf, size, soa.mname, offset))
            return std::error_code{(int)error::out_of_range, mdns_category()};
        if (!compressor.write_name(buf, size, soa.rname, offset))
            return std::error_code{(int)error::out_of_range, mdns_category()};
        std::error_code ec;
        offset += binary::pack<"!L3lL">(begin + offset, size - offset, ec,
                                        soa.serial, soa.refresh, soa.retry,
                                        soa.expire, soa.minimum);
        if (ec)
            return ec;
        break;
    }
    case record_type::WKS: {
        if (rdata_offset + 5 > size)
            return std::error_code{(int)error::out_of_range, mdns_category()};
        offset += 5;
        const auto &wks = std::get<rdata::wks>(record.data);
        std::error_code ec;
        binary::pack<"!LB">(begin + rdata_offset, size - rdata_offset, ec,
                            wks.address, wks.protocol);
        if (ec)
            return ec;
        break;
    }
    case record_type::PTR: {
        if (!compressor.write_name(buf, size, std::get<rdata::ptr>(record.data),
                                   offset))
            return std::error_code{(int)error::out_of_range, mdns_category()};
        break;
    }
    case record_type::HINFO: {
        // TODO:
        SAMLOG_DEBUG(auto sink) {
            char buf[256];
            sink({buf, sizeof(buf)}, "Unsupported record type: {}\n",
                 (uint16_t)record.type());
        };
        break;
    }
    case record_type::MX: {
        if (rdata_offset + 2 > size)
            return std::error_code{(int)error::out_of_range, mdns_category()};
        const auto &mx = std::get<rdata::mx>(record.data);
        binary::write_big<int16_t>(begin + rdata_offset, mx.preference);
        offset += 2;
        if (!compressor.write_name(buf, size, mx.exchange, offset))
            return std::error_code{(int)error::out_of_range, mdns_category()};
        break;
    }
    case record_type::TXT: {
        const auto &txt = std::get<rdata::txt>(record.data);
        if (rdata_offset + txt.size() > size)
            return std::error_code{(int)error::out_of_range, mdns_category()};
        offset += txt.size();
        std::copy(txt.begin(), txt.end(), begin + rdata_offset);
        break;
    }
    case record_type::AAAA: {
        if (rdata_offset + 16 > size)
            return std::error_code{(int)error::out_of_range, mdns_category()};
        offset += 16;
        const auto &ipv6 = std::get<rdata::aaaa>(record.data);
        std::copy(ipv6.begin(), ipv6.end(), begin + rdata_offset);
        break;
    }
    case record_type::SRV: {
        if (rdata_offset + 6 >= size)
            return std::error_code{(int)error::out_of_range, mdns_category()};
        const auto &srv = std::get<rdata::srv>(record.data);
        std::error_code ec;
        offset += binary::pack<"!3H">(begin + rdata_offset, size - rdata_offset,
                                      ec, srv.priority, srv.weight, srv.port);
        if (ec)
            return ec;
        // rfc2782:  Unless and until permitted by future standards action, name
        // compression is not to be used for this field.
        auto labels = std::views::split(srv.target, '.');
        std::size_t length = 0;
        for (const auto &label : labels) {
            length += 1 + label.size();
        }
        ++length;
        if (offset + length > size)
            return std::error_code{(int)error::out_of_range, mdns_category()};
        for (const auto &label : labels) {
            binary::write_big<uint8_t>(begin + offset, (uint8_t)label.size());
            std::copy(label.begin(), label.end(), begin + offset + 1);
            offset += 1 + label.size();
        }
        binary::write_big<uint8_t>(begin + offset, 0);
        ++offset;
        break;
    }
    case record_type::UknownType:
    default: {
        SAMLOG_DEBUG(auto sink) {
            char buf[256];
            sink({buf, sizeof(buf)}, "Write record Unknown record type: {}\n",
                 (uint16_t)record.type());
        };
    }
    }
    binary::write_big<uint16_t>(begin + rdata_offset - 2,
                                uint16_t(offset - rdata_offset));
    return {};
}

std::expected<std::size_t, std::error_code> message_t::write(void *buf,
                                                             std::size_t size) {
    header.questions_count = (uint16_t)questions.size();
    header.answers_count = (uint16_t)answers.size();
    header.authorities_count = (uint16_t)authorities.size();
    header.additionals_count = (uint16_t)additionals.size();
    auto ec = __write_header(buf, size, *this);
    if (ec)
        return std::unexpected(ec);
    ec = __verify_message(*this);
    if (ec)
        return std::unexpected(ec);

    //
    __sort_questions(questions);
    __sort_records(answers);
    __sort_records(authorities);
    __sort_records(additionals);

    // Compress
    name_compressor compressor;
    compressor.reserve(questions.size() + answers.size() + authorities.size() +
                       additionals.size());
    for (const auto &q : questions)
        compressor.prepare(q.name);
    for (const auto &record : answers)
        __add_record_to_string_pool(compressor, record);
    for (const auto &record : authorities)
        __add_record_to_string_pool(compressor, record);
    for (const auto &record : additionals)
        __add_record_to_string_pool(compressor, record);
    compressor.finally();

    // Write
    std::size_t offset = sizeof(header_t);
    for (const auto &record : questions) {
        if (!compressor.write_name(buf, size, record.name, offset))
            return std::unexpected(
                std::error_code{(int)error::out_of_range, mdns_category()});
        if (offset + 4 > size)
            return std::unexpected(
                std::error_code{(int)error::out_of_range, mdns_category()});
        binary::write_big<uint16_t>((char *)buf + offset,
                                    (uint16_t)record.type);
        binary::write_big<uint16_t>((char *)buf + offset + 2,
                                    (uint16_t)record.cls);
        offset += 4;
    }
    for (const auto &record : answers) {
        auto ec = __write_record(buf, size, record, offset, compressor);
        if (ec)
            return std::unexpected(ec);
    }
    for (const auto &record : authorities) {
        auto ec = __write_record(buf, size, record, offset, compressor);
        if (ec)
            return std::unexpected(ec);
    }
    for (const auto &record : additionals) {
        auto ec = __write_record(buf, size, record, offset, compressor);
        if (ec)
            return std::unexpected(ec);
    }
    return offset;
}

nlohmann::json message_t::header_t::to_json() const {
    nlohmann::json js;
    js["id"] = id;
    {
        nlohmann::json js_flags;
        js_flags["qr"] = flags.qr;
        js_flags["opcode"] = flags.opcode;
        js_flags["aa"] = flags.aa;
        js_flags["tc"] = flags.tc;
        js_flags["rd"] = flags.rd;
        js_flags["ra"] = flags.ra;
        js_flags["z"] = flags.z;
        js_flags["rcode"] = flags.rcode;
        js["flags"] = std::move(js_flags);
    }
    js["qdcount"] = questions_count;
    js["ancount"] = answers_count;
    js["nscount"] = authorities_count;
    js["arcount"] = additionals_count;
    return js;
}

nlohmann::json question_t::to_json() const {
    nlohmann::json js;
    js["name"] = name;
    js["type"] = (uint16_t)type;
    js["class"] = (uint16_t)cls;
    return js;
}

nlohmann::json record_t::to_json() const {
    nlohmann::json js;
    js["name"] = name;
    js["type"] = (uint16_t)type();
    js["class"] = (uint16_t)cls;
    js["ttl"] = ttl;
    js["rdlength"] = rdlength;

    switch (type()) {
    case record_type::A:
        js["a"] = net::ip::address_v4{std::get<rdata::a>(data)}.to_string();
        break;
    case record_type::AAAA: {
        const auto &aaaa = std::get<rdata::aaaa>(data);
        js["aaaa"] = net::ip::address_v6{aaaa}.to_string();
        break;
    }
    case record_type::CNAME:
        js["cname"] = std::get<rdata::cname>(data);
        break;
    case record_type::HINFO: {
        nlohmann::json rdata_js;
        rdata_js["cpu"] = std::get<rdata::hinfo>(data).cpu;
        rdata_js["os"] = std::get<rdata::hinfo>(data).os;
        js["hinfo"] = std::move(rdata_js);
        break;
    }
    case record_type::MX: {
        nlohmann::json rdata_js;
        rdata_js["preference"] = std::get<rdata::mx>(data).preference;
        rdata_js["exchange"] = std::get<rdata::mx>(data).exchange;
        js["mx"] = std::move(rdata_js);
        break;
    }
    case record_type::NS:
        js["ns"] = std::get<rdata::ns>(data);
        break;
    case record_type::PTR:
        js["ptr"] = std::get<rdata::ptr>(data);
        break;
    case record_type::SOA: {
        nlohmann::json rdata_js;
        const auto &soa = std::get<rdata::soa>(data);
        rdata_js["mname"] = soa.mname;
        rdata_js["rname"] = soa.rname;
        rdata_js["serial"] = soa.serial;
        rdata_js["refresh"] = soa.refresh;
        rdata_js["retry"] = soa.retry;
        rdata_js["expire"] = soa.expire;
        rdata_js["minimum"] = soa.minimum;
        js["soa"] = std::move(rdata_js);
        break;
    }
    case record_type::TXT:
        js["txt"] = std::get<rdata::txt>(data);
        break;
    case record_type::WKS: {
        nlohmann::json rdata_js;
        const auto &wks = std::get<rdata::wks>(data);
        rdata_js["ipv4"] = wks.address;
        rdata_js["protocol"] = wks.protocol;
        // TODO: bitmap
        js["wks"] = std::move(rdata_js);
        break;
    }
    case record_type::SRV: {
        nlohmann::json rdata_js;
        const auto &srv = std::get<rdata::srv>(data);
        rdata_js["priority"] = srv.priority;
        rdata_js["weight"] = srv.weight;
        rdata_js["port"] = srv.port;
        rdata_js["target"] = srv.target;
        js["srv"] = std::move(rdata_js);
    }
    }
    return js;
}

nlohmann::json message_t::to_json() const {
    nlohmann::json js;
    js["header"] = header.to_json();

    nlohmann::json question_js, answers_js, authorities_js, additional_js;
    question_js = nlohmann::json::array();
    answers_js = nlohmann::json::array();
    authorities_js = nlohmann::json::array();
    additional_js = nlohmann::json::array();
    for (const auto &q : questions) {
        question_js.push_back(q.to_json());
    }
    for (const auto &r : answers) {
        answers_js.push_back(r.to_json());
    }
    for (const auto &r : authorities) {
        authorities_js.push_back(r.to_json());
    }
    for (const auto &r : additionals) {
        additional_js.push_back(r.to_json());
    }

    js["question"] = std::move(question_js);
    js["answer"] = std::move(answers_js);
    js["authority"] = std::move(authorities_js);
    js["additional"] = std::move(additional_js);

    return js;
}

static bool __fast_parse_name(const char *&iter,
                              const char *const end) noexcept {
    while (iter < end) {
        uint8_t len = binary::read_big<uint8_t>(iter);
        if ((len & 0b11000000) == 0b11000000) {
            // pointer
            iter += 2;
            if (iter > end)
                return false;
            return true;
        } else if (len == 0) {
            // end
            ++iter;
            return true;
        } else {
            iter += len + 1;
        }
    }
    return false;
}

bool message_t::possible_valid(const void *buf, std::size_t size) noexcept {
    if (size < sizeof(header_t))
        return false;
    const char *iter = (const char *)buf + sizeof(header_t);
    const char *const end = (const char *)buf + size;

    uint16_t qdcount, arcount, nscount, addcount;
    std::error_code ec;
    binary::unpack<"!4H">((const char *)buf + 4, size - 4, ec, qdcount, arcount,
                          nscount, addcount);
    if (ec)
        return false;
    for (uint16_t i = 0; i < qdcount; ++i) {
        if (!__fast_parse_name(iter, end))
            return false;
        iter += 4;
        if (iter > end)
            return false;
    }

    const std::size_t record_count = arcount + nscount + addcount;
    for (std::size_t i = 0; i < record_count; ++i) {
        if (!__fast_parse_name(iter, end))
            return false;
        if (iter + 10 > end)
            return false;
        uint16_t rdlength = binary::read_big<uint16_t>(iter + 8);
        iter += 10 + rdlength;
        if (iter > end)
            return false;
    }

    return true;
}

record_type get_record_type(const generic_rdata_t &data) noexcept {
    switch (data.index()) {
    case 1:
        return record_type::A;
    case 2:
        return record_type::AAAA;
    case 3:
        return record_type::CNAME;
    case 4:
        return record_type::HINFO;
    case 5:
        return record_type::MX;
    case 6:
        return record_type::NS;
    case 7:
        return record_type::PTR;
    case 8:
        return record_type::SOA;
    case 9:
        return record_type::TXT;
    case 10:
        return record_type::WKS;
    case 11:
        return record_type::SRV;
    default:
        return record_type::UknownType;
    }
}

bool message_t::is_query() const noexcept { return header.flags.qr == 0; }

bool message_t::is_response() const noexcept { return header.flags.qr == 1; }

} // namespace mdns::dns