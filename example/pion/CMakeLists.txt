if(ASIOICE_ENABLE_SCTP_OVER_DTLS)
    add_executable(pion_example main.cpp)
    target_link_libraries(pion_example PRIVATE asioice_test_flags
                           OpenSSL::SSL OpenSSL::Crypto exsctp)
endif()
