#include "./transport.hpp"

#include <iostream>

void test_transport_compile() {
    exsctp::transport t;
}

int main() {
    test_transport_compile();
    std::cout << "Hello SCTP\n";
}