#include "./transport.hpp"

#include <iostream>

void test_transport_compile() {
    exsctp::transport t(std::shared_ptr<exsctp::any_io_interface>{nullptr}, {});

    {
        exsctp::message msg{0, 0, std::span<uint8_t>{}};
        std::optional<std::tuple<dcsctp::SendStatus>> status =
            stdexec::sync_wait(t.send(msg, {}));
    }
    {
        std::optional<std::tuple<dcsctp::DcSctpMessage>> msg =
            stdexec::sync_wait(t.read());
    }
    {
        std::optional<std::tuple<bool>> connected =
            stdexec::sync_wait(t.connect());
    }
    {
        std::optional<std::tuple<bool>> connected =
            stdexec::sync_wait(t.accept());
    }
    {
        std::optional<std::tuple<bool>> closed =
            stdexec::sync_wait(t.shutdown());
    }
    t.close();
}

int main() {
    test_transport_compile();
    std::cout << "Hello SCTP\n";
}