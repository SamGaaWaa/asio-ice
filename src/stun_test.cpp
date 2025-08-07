#include <chrono>
#include <iostream>

#include "address.hpp"
#include "base64.hpp"
#include "hash.hpp"
#include "json.hpp"
#include "stun.hpp"
#include "udp_connection.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <asio2exec.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
#include <asio/ip/udp.hpp>
#include <asio2exec.hpp>
namespace ice {
namespace net = asio;
}
#endif

// xor_mapped_address, software
static constexpr unsigned char packet_bytes1[] = {
    0x01, 0x01, 0x00, 0x38, 0x21, 0x12, 0xa4, 0x42, 0xb3, 0x89, 0x4c,
    0x59, 0x58, 0x15, 0x83, 0x65, 0x71, 0xc7, 0x82, 0xfb, 0x00, 0x20,
    0x00, 0x08, 0x00, 0x01, 0xcd, 0x94, 0xe1, 0xba, 0xa4, 0x24, 0x80,
    0x22, 0x00, 0x08, 0x6c, 0x69, 0x62, 0x6a, 0x75, 0x69, 0x63, 0x65,
    0x00, 0x08, 0x00, 0x14, 0xb7, 0x51, 0x7c, 0xa5, 0x81, 0x76, 0x02,
    0x61, 0x90, 0x21, 0x4d, 0x04, 0xc3, 0x4c, 0x94, 0x9b, 0x4b, 0x46,
    0x95, 0x6f, 0x80, 0x28, 0x00, 0x04, 0xa3, 0x28, 0x96, 0x52};

// priority, ice-controlling, username
static constexpr unsigned char packet_bytes2[] = {
    0x00, 0x01, 0x00, 0x50, 0x21, 0x12, 0xa4, 0x42, 0xb3, 0x89, 0x4c, 0x59,
    0x58, 0x15, 0x83, 0x65, 0x71, 0xc7, 0x82, 0xfb, 0x00, 0x24, 0x00, 0x04,
    0x6e, 0x7f, 0xff, 0xff, 0x80, 0x2a, 0x00, 0x08, 0xc6, 0x17, 0x82, 0xf0,
    0xb4, 0x26, 0x44, 0xbb, 0x80, 0x22, 0x00, 0x08, 0x6c, 0x69, 0x62, 0x6a,
    0x75, 0x69, 0x63, 0x65, 0x00, 0x06, 0x00, 0x09, 0x6e, 0x65, 0x77, 0x34,
    0x3a, 0x42, 0x31, 0x7a, 0x6a, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x14,
    0x66, 0x06, 0x21, 0x9d, 0x0b, 0x93, 0x04, 0xdb, 0xd8, 0xbc, 0xdb, 0x3a,
    0xdc, 0x8d, 0xfd, 0x9d, 0x6e, 0x3c, 0x18, 0x6d, 0x80, 0x28, 0x00, 0x04,
    0x82, 0x94, 0x6b, 0x2b};

// use-candidate
static constexpr unsigned char packet_bytes3[] = {
    0x00, 0x01, 0x00, 0x54, 0x21, 0x12, 0xa4, 0x42, 0x1a, 0x05, 0x43, 0x88,
    0x09, 0x9f, 0xdc, 0x93, 0x7e, 0xdb, 0x69, 0xb0, 0x00, 0x24, 0x00, 0x04,
    0x6e, 0x7f, 0xff, 0xff, 0x00, 0x25, 0x00, 0x00, 0x80, 0x2a, 0x00, 0x08,
    0xd8, 0x8b, 0x02, 0x6c, 0x62, 0xb5, 0x0e, 0xa6, 0x80, 0x22, 0x00, 0x08,
    0x6c, 0x69, 0x62, 0x6a, 0x75, 0x69, 0x63, 0x65, 0x00, 0x06, 0x00, 0x09,
    0x4b, 0x67, 0x4c, 0x72, 0x3a, 0x4e, 0x53, 0x42, 0x64, 0x00, 0x00, 0x00,
    0x00, 0x08, 0x00, 0x14, 0x7a, 0xf5, 0xd9, 0x05, 0x63, 0x55, 0xb2, 0x1c,
    0xab, 0xbe, 0xd0, 0x86, 0x45, 0x69, 0xc2, 0x24, 0xcf, 0x3e, 0xbf, 0xf3,
    0x80, 0x28, 0x00, 0x04, 0x6b, 0xb7, 0xbb, 0xd8};

// ice-controlled
static constexpr unsigned char packet_bytes4[] = {
    0x00, 0x01, 0x00, 0x50, 0x21, 0x12, 0xa4, 0x42, 0xba, 0x84, 0x30, 0x66,
    0xe4, 0x89, 0x2d, 0xb1, 0x9e, 0x7d, 0x6e, 0x36, 0x00, 0x24, 0x00, 0x04,
    0x6e, 0x7f, 0xff, 0xff, 0x80, 0x29, 0x00, 0x08, 0x14, 0x55, 0xaf, 0x1e,
    0x43, 0x77, 0x27, 0x75, 0x80, 0x22, 0x00, 0x08, 0x6c, 0x69, 0x62, 0x6a,
    0x75, 0x69, 0x63, 0x65, 0x00, 0x06, 0x00, 0x09, 0x7a, 0x42, 0x74, 0x77,
    0x3a, 0x4e, 0x67, 0x70, 0x35, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x14,
    0x3f, 0xba, 0x60, 0x79, 0x5c, 0xfa, 0xee, 0x3a, 0xbe, 0x37, 0x9a, 0x16,
    0xa2, 0x0e, 0xd2, 0xcc, 0xa4, 0x3f, 0x22, 0x1a, 0x80, 0x28, 0x00, 0x04,
    0x4f, 0x6c, 0x6e, 0xb0};

// nonce, realm, userhash, message-integrity
static constexpr unsigned char packet_bytes5[] = {
    0x00, 0x01, 0x00, 0x90, // Request type and message length
    0x21, 0x12, 0xa4, 0x42, // Magic cookie
    0x78, 0xad, 0x34, 0x33, // Transaction ID
    0xc6, 0xad, 0x72, 0xc0, //
    0x29, 0xda, 0x41, 0x2e, //
    0x00, 0x1e, 0x00, 0x20, // USERHASH attribute header
    0x4a, 0x3c, 0xf3, 0x8f, // Userhash value (32 bytes)
    0xef, 0x69, 0x92, 0xbd, //
    0xa9, 0x52, 0xc6, 0x78, //
    0x04, 0x17, 0xda, 0x0f, //
    0x24, 0x81, 0x94, 0x15, //
    0x56, 0x9e, 0x60, 0xb2, //
    0x05, 0xc4, 0x6e, 0x41, //
    0x40, 0x7f, 0x17, 0x04, //
    0x00, 0x15, 0x00, 0x29, // NONCE attribute header
    0x6f, 0x62, 0x4d, 0x61, // Nonce value and padding (3 bytes)
    0x74, 0x4a, 0x6f, 0x73, //
    0x32, 0x41, 0x41, 0x41, //
    0x43, 0x66, 0x2f, 0x2f, //
    0x34, 0x39, 0x39, 0x6b, //
    0x39, 0x35, 0x34, 0x64, //
    0x36, 0x4f, 0x4c, 0x33, //
    0x34, 0x6f, 0x4c, 0x39, //
    0x46, 0x53, 0x54, 0x76, //
    0x79, 0x36, 0x34, 0x73, //
    0x41, 0x00, 0x00, 0x00, //
    0x00, 0x14, 0x00, 0x0b, // REALM attribute header
    0x65, 0x78, 0x61, 0x6d, // Realm value (11 bytes) and padding (1 byte)
    0x70, 0x6c, 0x65, 0x2e, //
    0x6f, 0x72, 0x67, 0x00, //
    0x00, 0x1d, 0x00, 0x04, // PASSWORD-ALGORITHM attribute header
    0x00, 0x02, 0x00, 0x00, // PASSWORD-ALGORITHM value (4 bytes)
    0x00, 0x1c, 0x00, 0x20, // MESSAGE-INTEGRITY-SHA256 attribute header
    0xb5, 0xc7, 0xbf, 0x00, // HMAC-SHA256 value
    0x5b, 0x6c, 0x52, 0xa2, //
    0x1c, 0x51, 0xc5, 0xe8, //
    0x92, 0xf8, 0x19, 0x24, //
    0x13, 0x62, 0x96, 0xcb, //
    0x92, 0x7c, 0x43, 0x14, //
    0x93, 0x09, 0x27, 0x8c, //
    0xc6, 0x51, 0x8e, 0x65, //
};

void parse_test1() {
    const auto begin = std::chrono::high_resolution_clock::now();
    ice::stun::message resp;
    bool success = resp.parse(packet_bytes1, sizeof(packet_bytes1));
    const auto end = std::chrono::high_resolution_clock::now();
    if (!success)
        std::cout << "Parse response1 failed!\n";
    else {
        std::cout << "Success!\n";
        std::cout << resp.to_string() << '\n';
    }
    auto dura =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "Parsing a stun message takes " << dura.count() << "ns.\n\n";
}

void parse_test2() {
    const auto begin = std::chrono::high_resolution_clock::now();
    ice::stun::message resp;
    bool success = resp.parse(packet_bytes2, sizeof(packet_bytes2));
    const auto end = std::chrono::high_resolution_clock::now();
    if (!success)
        std::cout << "Parse response2 failed!\n";
    else {
        std::cout << "Success!\n";
        std::cout << resp.to_string() << '\n';
    }
    auto dura =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "Parsing a stun message takes " << dura.count() << "ns.\n\n";
}

void parse_test3() {
    const auto begin = std::chrono::high_resolution_clock::now();
    ice::stun::message resp;
    bool success = resp.parse(packet_bytes3, sizeof(packet_bytes3));
    const auto end = std::chrono::high_resolution_clock::now();
    if (!success)
        std::cout << "Parse response3 failed!\n";
    else {
        std::cout << "Success!\n";
        std::cout << resp.to_string() << '\n';
    }
    auto dura =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "Parsing a stun message takes " << dura.count() << "ns.\n\n";
}

void parse_test4() {
    const auto begin = std::chrono::high_resolution_clock::now();
    ice::stun::message resp;
    bool success = resp.parse(packet_bytes4, sizeof(packet_bytes4));
    const auto end = std::chrono::high_resolution_clock::now();
    if (!success)
        std::cout << "Parse response4 failed!\n";
    else {
        std::cout << "Success!\n";
        std::cout << resp.to_string() << '\n';
    }
    auto dura =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "Parsing a stun message takes " << dura.count() << "ns.\n\n";
}

void parse_test5() {
    const auto begin = std::chrono::high_resolution_clock::now();
    ice::stun::message resp;
    bool success = resp.parse(packet_bytes5, sizeof(packet_bytes5));
    const auto end = std::chrono::high_resolution_clock::now();
    if (!success)
        std::cout << "Parse response5 failed!\n";
    else {
        std::cout << "Success!\n";
        std::cout << resp.to_string() << '\n';
    }
    auto dura =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "Long-term authentication with password \"TheMatrIX\"\n";
    const auto &algo = resp.pwd_algorithm.value();
    std::string password = algo.get_hmac_key(
        nlohmann::json::parse(R"("\u30DE\u30C8\u30EA\u30C3\u30AF\u30B9")")
            .get<std::string>(),
        resp.realm, "TheMatrIX");
    for (const auto &i : resp.integrities) {
        std::cout << "Integrity check with hmac key \""
                  << ice::hash::to_hex(password.data(), password.size())
                  << "\"\n";
        if (i.verify(password, resp)) {
            std::cout << "Check integrity success!\n";
        } else {
            std::cout << "Check integrity failed!\n";
        }
    }
    std::cout << "Parsing a stun message takes " << dura.count() << "ns.\n\n";
}

void parse_base64() {
    std::cout << "\nBase64:" << std::ends;
    std::string b64;
    std::cin >> b64;
    std::vector<std::byte> raw;
    raw.resize(ice::base64::decoded_size(b64.size()));
    raw.resize(ice::base64::decode(raw.data(), b64.data(), b64.size()).first);

    const auto begin = std::chrono::high_resolution_clock::now();
    ice::stun::message resp;
    bool success = resp.parse(raw.data(), raw.size());
    const auto end = std::chrono::high_resolution_clock::now();
    if (!success)
        std::cout << "Parse base64 failed!\n";
    else {
        std::cout << "Success!\n";
        std::cout << resp.to_string() << '\n';
    }
    auto dura =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "Parsing a stun message takes " << dura.count() << "ns.\n\n";
}

void write_test() {
    ice::stun::message msg, parsed;
    msg.mapped_address.emplace(ice::net::ip::make_address("127.0.0.1"), 8080);
    msg.integrities.emplace_back(ice::stun::message::integrity::SHA1);
    msg.integrities.emplace_back(ice::stun::message::integrity::SHA256);
    msg.use_fingerprint(true);
    msg.set_hmac_key("Hello");

    std::cout << "Should write " << msg.serialized_size() << " bytes.\n";
    char buf[20 + 4 + 4 + 4 + 4 + 20 + 4 + 32 + 4 + 4 + 4 + 8];
    int ret = msg.write_to(buf, sizeof(buf));
    if (ret < 0) {
        std::cerr << "Write test failed.\n";
        return;
    }
    std::cout << "Write " << ret << " bytes.\n";
    if (!parsed.parse(buf, ret)) {
        std::cerr << "Re-parse failed.\n";
        return;
    }
    std::cout << "re-parse success!\n";
    for (auto &integrity : parsed.integrities) {
        if (!integrity.verify("Hello", parsed)) {
            std::cerr << "Message integrity check failed.\n";
            return;
        }
        std::cout << "Integrity check success.\n";
    }
    auto str = parsed.to_string();
    std::cout << "Msg:\n" << str << '\n';
    std::cout << "Success, write " << ret << " bytes.\n\n";
}

void request_test() {
    using namespace ice;

    net::io_context ctx;
    net::ip::udp::resolver resolver(ctx);

    // auto resolve_result = resolver.resolve("stun.l.google.com", "19302");
    // auto resolve_result = resolver.resolve("0.0.0.0", "13478");
    // auto resolve_result = resolver.resolve("113.96.17.249", "20002");
    auto resolve_result = resolver.resolve("14.29.112.241", "20002");
    if (resolve_result.empty()) {
        std::cerr << "Resolve error\n";
        return;
    }

    const auto &ep = resolve_result.begin()->endpoint();
    std::cout << "STUN server: " << ep.address().to_string() << ':' << ep.port()
              << '\n';

    net::ip::udp::socket sock(ctx, net::ip::udp::v4());

    stun::message req;
    req.method = stun::method_t::STUN_METHOD_BINDING;
    req.cls = stun::class_t::STUN_CLASS_REQUEST;
    req.use_fingerprint(true);
    req.transaction_id = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};

    char buf[1500];
    int n = req.write_to(buf, sizeof(buf));
    if (n < 0) {
        std::cerr << "Write buffer error\n";
        return;
    }
    std::cout << "Write " << n << " bytes to buffer\n";

    try {
        sock.send_to(net::buffer(buf, n), ep);
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return;
    }
    std::cout << "Finish\n";

    net::ip::udp::endpoint server_ep;
    std::size_t nread;
    try {
        nread = sock.receive_from(net::buffer(buf, sizeof(buf)), server_ep);
        std::cout << "Read " << nread << " bytes from "
                  << server_ep.address().to_string() << ':' << server_ep.port()
                  << '\n';
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return;
    }
    stun::message resp;
    if (!resp.parse(buf, nread)) {
        std::cerr << "Parse response failed\n";
        return;
    }
    std::cout << resp.to_string() << '\n';
    std::cout << "Finish\n\n";
}

int main() {
    std::cout << "This is stun test.\n";

    parse_test1();
    parse_test2();
    parse_test3();
    parse_test4();
    parse_test5();

    write_test();
    // while (true)
    //{
    //    parse_base64();
    //}
    request_test();
}