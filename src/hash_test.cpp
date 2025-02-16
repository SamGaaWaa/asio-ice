#include "hash.hpp"

#include <iostream>

using namespace ice;

void md5_test() {
    const char *str = "hello world";
    char res[16];
    hash::MD5(res, std::string_view(str), std::string(", I love you"));
    char hex[33];
    hash::to_hex(res, sizeof(res), hex);
    hex[32] = '\0';
    std::cout << hex << '\n';
}

int main() { md5_test(); }