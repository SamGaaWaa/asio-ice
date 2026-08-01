#include "asioice/candidate.hpp"
#include "hash.hpp"
#include "json.hpp"
#include "asioice/detail/string_utils.hpp"
#include "samlog.hpp"

// #include <ctre.hpp>

#include <charconv>
#include <cstring>
#include <string>
#include <format>

namespace asioice {

std::string_view type_to_string(candidate_type type) noexcept {
    switch (type) {
    case candidate_type::host:
        return "host";
    case candidate_type::srflx:
        return "srflx";
    case candidate_type::prflx:
        return "prflx";
    case candidate_type::relay:
        return "relay";
    }
    return "unknown";
}

static std::string md5_hex(const std::string &key) {
    unsigned char digest[16];
    hash::MD5(digest, key);
    std::string res(16 * 2, '0');
    hash::to_hex(digest, sizeof(digest), res.data());
    return res;
}

std::string candidate_foundation(candidate_type type,
                                 std::string_view transport,
                                 const net::ip::address &base_address,
                                 std::optional<net::ip::address> server) {
    std::string key;
    std::string_view type_str = type_to_string(type);
    std::string addr_str = base_address.to_string();
    key.reserve(type_str.size() + 2 + transport.size() + addr_str.size() + 17);
    key += type_str;
    key += '|';
    key += transport;
    key += '|';
    key += addr_str;
    if (type != asioice::candidate_type::host) {
        key += '|';
        key += server.value().to_string();
    }
    return md5_hex(key);
}

uint32_t candidate_priority(uint8_t component, candidate_type type,
                            uint32_t preference) noexcept {
    uint32_t type_pref = [type] {
        switch (type) {
        case candidate_type::host:
            return 126;
        case candidate_type::srflx:
            return 100;
        case candidate_type::prflx:
            return 110;
        default:
            return 0;
        }
    }();
    return (uint32_t{1} << 24) * type_pref + (uint32_t{1} << 8) * preference +
           (256 - component);
}

std::string candidate::to_string(int indent) const {
    nlohmann::json j;

    j["foundation"] = this->foundation;
    j["component"] = this->component;
    j["transport"] = this->transport_type;
    j["priority"] = this->priority;
    j["endpoint"] = this->endpoint.to_string();
    j["type"] = type_to_string(this->type);

    if (this->related) {
        j["related"] = this->related->to_string();
    }
    if (!this->tcptype.empty()) {
        j["tcptype"] = this->tcptype;
    }
    if (this->generation) {
        j["generation"] = *this->generation;
    }

    return j.dump(indent);
}

bool candidate::can_pair_with(const candidate &other) const noexcept {
    return this->type != asioice::candidate_type::srflx &&
           this->component == other.component &&
           ((this->endpoint.address().is_v4() &&
             other.endpoint.address().is_v4()) ||
            (this->endpoint.address().is_v6() &&
             other.endpoint.address().is_v6())) &&
           utils::nceq(this->transport_type, other.transport_type);
}

std::optional<candidate> candidate::from_sdp(std::string_view sdp,
                                             std::size_t *nread) noexcept {
    // 1. 检查前缀
    if (!sdp.starts_with("candidate:")) {
        SAMLOG_WARN(auto sink) { sink("Invalid SDP: {}\n", sdp); };
        return {};
    }

    // 剥离前缀
    std::string_view rest = sdp.substr(10); // len("candidate:")
    const std::size_t initial_size = sdp.size();

    // 辅助函数：跳过空格并提取下一个 token
    auto next_token = [](std::string_view &v) -> std::string_view {
        while (!v.empty() && v.front() == ' ')
            v.remove_prefix(1);
        if (v.empty())
            return {};
        auto pos = v.find(' ');
        auto token = v.substr(0, pos);
        v.remove_prefix(pos == std::string_view::npos ? v.size() : pos);
        return token;
    };

    // 提取基础字段
    auto fd_str = next_token(rest);
    auto com_str = next_token(rest);
    auto tran_str = next_token(rest);
    auto pri_str = next_token(rest);
    auto addr_str = next_token(rest);
    auto port_str = next_token(rest);
    auto typ_keyword = next_token(rest);
    auto type_str = next_token(rest);

    // 基础字段验证：不能为空，且 "typ" 关键字必须存在
    if (fd_str.empty() || com_str.empty() || tran_str.empty() ||
        pri_str.empty() || addr_str.empty() || port_str.empty() ||
        typ_keyword != "typ" || type_str.empty()) {
        SAMLOG_WARN(auto sink) { sink("Invalid SDP: {}\n", sdp); };
        return {};
    }

    candidate c;

    // foundation
    c.foundation = fd_str;

    // component
    if (std::from_chars(com_str.data(), com_str.data() + com_str.size(),
                        c.component)
            .ec != std::errc{})
        return {};

    // transport
    c.transport_type = tran_str;

    // priority
    if (std::from_chars(pri_str.data(), pri_str.data() + pri_str.size(),
                        c.priority)
            .ec != std::errc{})
        return {};

        // address & port
#if ASIOICE_USE_BOOST_ASIO
    boost::system::error_code ec;
#else
    net::error_code ec;
#endif
    net::ip::address addr;
    if (addr_str.ends_with(".local")) {
        c.mdns_host = addr_str;
    } else {
        addr = net::ip::make_address(addr_str, ec);
        if (ec)
            return {};
    }

    uint16_t port = 0;
    if (std::from_chars(port_str.data(), port_str.data() + port_str.size(),
                        port)
            .ec != std::errc{})
        return {};
    c.endpoint = asioice::endpoint(addr, port);

    // candidate type
    if (type_str == "host")
        c.type = candidate_type::host;
    else if (type_str == "srflx")
        c.type = candidate_type::srflx;
    else if (type_str == "relay")
        c.type = candidate_type::relay;
    else
        return {};

    // 提取可选字段 raddr 和 rport
    // 注意：原正则中 raddr 和 rport 是独立的可选捕获组，但原代码逻辑中，只有当
    // raddr 存在时才会填充 related。 这里严格复刻原逻辑：遇到 raddr
    // 关键字才处理，处理时顺便检查后方是否有 rport。
    auto raddr_keyword = next_token(rest);
    if (raddr_keyword == "raddr") {
        auto raddr_str = next_token(rest);
        if (raddr_str.empty())
            return {}; // raddr 关键字后必须有值

        net::ip::address raddr;
        if (raddr_str.ends_with(".local")) {
            c.mdns_related = raddr_str;
        } else {
            raddr = net::ip::make_address(raddr_str, ec);
            if (ec)
                return {};
        }

        uint16_t rport = 0;
        auto rport_keyword = next_token(rest);
        if (rport_keyword == "rport") {
            auto rport_str = next_token(rest);
            if (rport_str.empty())
                return {}; // rport 关键字后必须有值

            if (std::from_chars(rport_str.data(),
                                rport_str.data() + rport_str.size(), rport)
                    .ec != std::errc{})
                return {};
        }
        c.related.emplace(raddr, rport);
    }

    // nread 计算：总长度减去未解析完的长度，即为已成功匹配的长度
    if (nread)
        *nread = initial_size - rest.size();

    return c;
}

std::string candidate::to_sdp() const {
    auto sdp = std::format(
        "candidate:{} {} {} {} {} {} typ {}", this->foundation,
        (int)this->component, this->transport_type, this->priority,
        (!this->mdns_host.empty() ? this->mdns_host
                                  : this->endpoint.address().to_string()),
        this->endpoint.port(), type_to_string(this->type));
    if (this->related) {
        std::format_to(std::back_inserter(sdp), " raddr {} rport {}",
                       (!this->mdns_related.empty()
                            ? this->mdns_related
                            : this->related->address().to_string()),
                       this->related->port());
    }
    if (!this->tcptype.empty())
        std::format_to(std::back_inserter(sdp), " tcptype {}", this->tcptype);
    return sdp;
}

} // namespace asioice