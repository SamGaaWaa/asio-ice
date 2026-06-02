mkdir .\mingw-build
pushd .\mingw-build

cmake -G "MinGW Makefiles" .. ^
        -DBoost_DIR="C:\Boost\lib\cmake\Boost-1.90.0" ^
        -DSTDEXEC_DIR="D:\openSource\stdexec\include" ^
        -DASIOICE_USE_BOOST_ASIO=ON ^
        -DCMAKE_BUILD_TYPE=Debug ^
        -DCMAKE_C_COMPILER=gcc ^
        -DCMAKE_CXX_COMPILER=g++ ^
        -DOPENSSL_ROOT_DIR="D:\\openSource\\openssl-3.1.0\\x64" ^
        -DASIOICE_ENABLE_SCTP_OVER_DTLS=ON

mingw32-make.exe -j8

popd