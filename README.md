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


# Author
ZHANG JIAXIAO
