if(ASIOICE_ENABLE_SCTP_OVER_DTLS)
    add_executable(browser_example main.cpp)
    target_link_libraries(browser_example PRIVATE asioice_test_flags
                           OpenSSL::SSL OpenSSL::Crypto exsctp)
endif()
