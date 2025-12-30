# Overview
Implemented an ML-KEM adapter and benchmarking tools to connect liboqs and wolfSSL, and performed performance optimization and evaluation of liboqs.

# Description
This repository contains an adapter to integrate the ML-KEM implementations of liboqs and wolfSSL, as well as a benchmarking program for performance evaluation. The benchmark repeatedly runs ML-KEM KeyGen / Encap / Decap and records metrics such as ops/sec and ms/op (optionally including the median, variance, and standard deviation).

# Requirements
OS: macOS 15.6.1 (Apple Silicon / arm64)
CPU: Apple M1
Compiler: Apple clang 17.0.0 (Xcode Command Line Tools)
Build tools:

liboqs version 0.15.0
wolfSSL version 5.8.4

# Install / Build
### Build and install wolfSSL
git clone https://github.com/wolfSSL/wolfssl.git

cd wolfssl

./autogen.sh

./configure \
  --prefix="$HOME/local/wolfssl-mlkem-neon" \
  --enable-mlkem=yes,cache-a \
  --enable-dilithium \
  --enable-all-asm \
  --enable-cryptonly \
  --disable-shared \
  CFLAGS="-O3 -mcpu=apple-m1"

  make -j"$(sysctl -n hw.ncpu)"
make install

### Build and install liboqs
brew install cmake ninja openssl@3 wget doxygen graphviz astyle valgrind
pip3 install pytest pytest-xdist pyyaml

git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
  
mkdir build && cd build

cmake .. -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$HOME/local/wolfssl-mlkem-neon" \
  -DCMAKE_C_FLAGS="-O3 -mcpu=apple-m1 -I$HOME/local/wolfssl-mlkem-neon/include" \
  -DCMAKE_EXE_LINKER_FLAGS="-L$HOME/local/wolfssl-mlkem-neon/lib"
  
ninja


# Author
ZHANG JIAXIAO
