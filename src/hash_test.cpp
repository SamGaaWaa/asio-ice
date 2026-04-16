#include "hash.hpp"

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace asioice;

void md5_test() {
    const char *str = "hello world";
    char res[16];
    hash::MD5(res, std::string_view(str), std::string(", I love you"));
    char hex[33];
    hash::to_hex(res, sizeof(res), hex);
    hex[32] = '\0';
    if (std::memcmp(hex, "34a663aed00b852f7fc313f45ab57fe0", 32) != 0) {
        throw std::runtime_error("md5 test failed");
    }
}

void sha1_test() {
    const char *str = "hello world";
    char res[20];
    hash::SHA1(res, std::string_view(str), std::string(", I love you"));
    char hex[41];
    hash::to_hex(res, sizeof(res), hex);
    hex[40] = '\0';
    if (std::memcmp(hex, "f596e4c08897527eda2a77fb08d568b798389e8e", 40) != 0) {
        throw std::runtime_error("sha1 test failed");
    }
}

void sha256_test() {
    const char *str = "hello world";
    char res[32];
    hash::SHA256(res, std::string_view(str), std::string(", I love you"));
    char hex[65];
    hash::to_hex(res, sizeof(res), hex);
    hex[64] = '\0';
    if (std::memcmp(
            hex,
            "d9d1c4a414095ed151d7370aa6e1c212c4b2ff64c39b8270218f46aba77d75a1",
            64) != 0) {
        throw std::runtime_error("sha256 test failed");
    }
}

void sha512_test() {
    const char *str = "hello world";
    char res[64];
    hash::SHA512(res, std::string_view(str), std::string(", I love you"));
    char hex[129];
    hash::to_hex(res, sizeof(res), hex);
    hex[128] = '\0';
    if (std::memcmp(
            hex,
            "a3f0fb4096ba7c018beb275573195b2342b4d50fb0c4703fbbdf20463233c6f3a9"
            "15cbc864a33326e7095357e58b24e9cf150711d2d2e7f45af1b2aab7a91e18",
            128) != 0) {
        throw std::runtime_error("sha512 test failed");
    }
}

void hmac_md5_test() {
    hash::hmac_context<hash::md5> ctx("1234");
    std::string_view str("hello world");
    ctx.update(str.data(), str.size());
    char res[16];
    ctx.final(res, sizeof(res));
    char hex[33];
    hash::to_hex(res, sizeof(res), hex);
    hex[32] = '\0';
    if (std::memcmp(hex, "0ce58ce59370a4dab96d0118ba02becc", 32) != 0) {
        throw std::runtime_error("hmac_md5 test failed");
    }
}

void hmac_sha1_test() {
    hash::hmac_context<hash::sha1> ctx("1234");
    std::string_view str("hello world");
    ctx.update(str.data(), str.size());
    char res[20];
    ctx.final(res, sizeof(res));
    char hex[41];
    hash::to_hex(res, sizeof(res), hex);
    hex[40] = '\0';
    if (std::memcmp(hex, "f319a344cbeb69d1096f48b7416352cbf9de641e", 40) != 0) {
        throw std::runtime_error("hmac_sha1 test failed");
    }
}

void hmac_sha256_test() {
    hash::hmac_context<hash::sha256> ctx("1234");
    std::string_view str("hello world");
    ctx.update(str.data(), str.size());
    char res[32];
    ctx.final(res, sizeof(res));
    char hex[65];
    hash::to_hex(res, sizeof(res), hex);
    hex[64] = '\0';
    if (std::memcmp(
            hex,
            "5ce0fe96fe498b021f039f8abcda8c26f7f3b0fdbd66c9e0510568df7114bfec",
            64) != 0) {
        throw std::runtime_error("hmac_sha256 test failed");
    }
}

void hmac_sha512_test() {
    hash::hmac_context<hash::sha512> ctx("1234");
    std::string_view str("hello world");
    ctx.update(str.data(), str.size());
    char res[64];
    ctx.final(res, sizeof(res));
    char hex[129];
    hash::to_hex(res, sizeof(res), hex);
    hex[128] = '\0';
    if (std::memcmp(
            hex,
            "2db0c19319b7c681bf03111e9ab16b1dfeda50414e0c68e1fa73c54286e201507b"
            "8ad192dd803410b9ed05bef635eda7391b30d948e836c3627f72937ffab5a7",
            128) != 0) {
        throw std::runtime_error("hmac_sha512 test failed");
    }
}

void thread_safe_test() {
    std::vector<std::thread> threads;
    for (int i = 0; i < 100; ++i) {
        threads.emplace_back([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            for (int j = 0; j < 100; ++j) {
                md5_test();
                sha1_test();
                sha256_test();
                sha512_test();
                hmac_md5_test();
                hmac_sha1_test();
                hmac_sha256_test();
                hmac_sha512_test();
            }
        });
    }
    for (auto &t : threads) {
        t.join();
    }
}

int main() {
    md5_test();
    sha1_test();
    sha256_test();
    sha512_test();

    hmac_md5_test();
    hmac_sha1_test();
    hmac_sha256_test();
    hmac_sha512_test();

    thread_safe_test();
}