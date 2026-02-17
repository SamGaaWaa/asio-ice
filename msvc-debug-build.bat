pushd .\msvc-build

cmake -G "Visual Studio 18 2026" .. ^
        -DBoost_DIR="C:\Boost\lib\cmake\Boost-1.90.0" ^
        -DSTDEXEC_DIR="D:\openSource\asio2exec\stdexec" ^
        -DASIOICE_USE_BOOST_ASIO=ON ^
        -DOPENSSL_DIR="D:\openSource\openssl-3.1.0\x64" ^
        -DOPENSSL_LIB_DIR="D:\openSource\openssl-3.1.0\x64\lib" ^
        -DOPENSSL_INCLUDE_DIR="D:\openSource\openssl-3.1.0\x64\include"

cmake --build .

popd