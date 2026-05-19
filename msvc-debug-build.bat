pushd .\msvc-build

cmake -G "Visual Studio 18 2026" .. ^
        -DBoost_DIR="C:\Boost\lib\cmake\Boost-1.90.0" ^
        -DSTDEXEC_DIR="D:\openSource\stdexec\include" ^
        -DASIOICE_USE_BOOST_ASIO=ON ^
        -DOPENSSL_ROOT_DIR="D:\\openSource\\openssl-3.1.0\\x64" ^
        -DASIOICE_ENABLE_SCTP_OVER_DTLS=ON

cmake --build .

popd