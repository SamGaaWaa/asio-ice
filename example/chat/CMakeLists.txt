if(ASIOICE_ENABLE_SCTP_OVER_DTLS)
    add_executable(chat_example main.cpp)
    target_link_libraries(chat_example PRIVATE asioice_test_flags
                           OpenSSL::SSL OpenSSL::Crypto exsctp)
endif()
