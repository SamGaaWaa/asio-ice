if(ASIOICE_ENABLE_DTLS)
    add_executable(ffmpeg_example main.cpp)
    target_link_libraries(ffmpeg_example PRIVATE asioice_test_flags
                           OpenSSL::SSL OpenSSL::Crypto)
endif()
