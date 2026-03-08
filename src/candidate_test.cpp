#include "candidate.hpp"

#include <iostream>

void verify(std::string_view sdp)
{
    std::cout << "parsing \"" << sdp << "\"\n";
    auto c = ice::candidate::from_sdp(sdp);
    if (c) {
        std::cout << "parsed success: " << c->to_sdp() << '\n';
    } else {
        std::cout << "parsed failed\n";
    }
    std::cout << '\n';
}

int main() {
    verify("candidate:3 1 UDP 1234567890 10.0.0.1 3478 typ relay");
    verify("candidate:3 1 UDP 123456789 3478 typ relay");

    std::string line;
    while (true) {
        std::cout << "sdp:";
        std::getline(std::cin, line);
        if (line == "quit")
            break;
        verify(line);
    }
}