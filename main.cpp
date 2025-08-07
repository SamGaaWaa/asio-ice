#include <openssl/sha.h>

#include <iostream>
#include <iomanip>
#include <sstream>

#include "ice.hpp"

std::string sha512(const std::string &str) {
    unsigned char hash[SHA512_DIGEST_LENGTH]; // 存储结果
    SHA512(reinterpret_cast<const unsigned char *>(str.c_str()), str.size(),
           hash);

    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
    }
    return ss.str();
}

void test_sha512() {
    std::string input = "Hello, OpenSSL!";
    std::string output = sha512(input);

    std::cout << "Input: " << input << std::endl;
    std::cout << "SHA-512 Hash: " << output << std::endl;
}

void json_test() {
    // boost::json::value v = boost::json::parse(R"({"name": "John", "age": 30,
    // "city": "New York"})"); std::cout << v.at("name").as_string() <<
    // std::endl;
}

int main() {
    // test_sha512();
    // json_test();
    ice::debug_test();
}