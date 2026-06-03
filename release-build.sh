#!/bin/bash
mkdir -p clang-build
pushd clang-build

cmake .. \
        -DBoost_DIR=/home/sam/opensource/boost_install/lib/cmake/Boost-1.89.0 \
        -DSTDEXEC_DIR=/home/sam/opensource/stdexec/include \
        -DASIOICE_USE_BOOST_ASIO=ON \
        -DCMAKE_BUILD_TYPE=Release \
 	-DCMAKE_C_COMPILER=clang-20 \
	-DCMAKE_CXX_FLAGS="-stdlib=libc++ -O3 -DNDEBUG" \
	-DCMAKE_CXX_COMPILER=clang++-20 \
        -DASIOICE_ENABLE_SCTP_OVER_DTLS=ON
make -j8
popd
