if(ASIOICE_ENABLE_SCTP_OVER_DTLS)
    add_executable(werift_example main.cpp)
    target_link_libraries(werift_example PRIVATE asioice_test_flags
                           OpenSSL::SSL OpenSSL::Crypto exsctp)
endif()
