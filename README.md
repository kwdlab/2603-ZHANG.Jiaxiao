# Overview
Implemented an ML-KEM adapter and benchmarking tools to connect liboqs and wolfSSL, and performed performance optimization and evaluation of liboqs.

# Description
This repository contains an adapter to integrate the ML-KEM implementations of liboqs and wolfSSL, as well as a benchmarking program for performance evaluation. The benchmark repeatedly runs ML-KEM KeyGen / Encap / Decap and records metrics such as ops/sec and ms/op (optionally including the median, variance, and standard deviation).

# Requirements
OS: macOS 15.6.1 (Apple Silicon / arm64)

CPU: Apple M1

Compiler: Apple clang 17.0.0 (Xcode Command Line Tools)

liboqs version 0.15.0

wolfSSL version 5.8.4

# Project Structure

### Directory layout
Place `liboqs/` and `wolfssl/` under the same parent directory (recommended):

- `<workdir>/liboqs/`   : liboqs source tree (this repository is based on it)
- `<workdir>/wolfssl/`  : wolfSSL source tree (built and installed to `$HOME/local/wolfssl-mlkem-neon`)

### Custom files (added to liboqs)
The following custom files are placed under `liboqs/tests/`:

- `liboqs/tests/example_kem_cho.c`
- `liboqs/tests/kem_ml_kem_liboqs_to_wolfssl_adapter.c`
- `liboqs/tests/kem_ml_kem_liboqs_to_wolfssl_adapter.h`

### CMake changes
In `liboqs/tests/CMakeLists.txt`, add the following lines to build the custom benchmark:

```cmake
# cho tests
add_executable(example_kem_cho example_kem_cho.c kem_ml_kem_liboqs_to_wolfssl_adapter.c)
target_link_libraries(example_kem_cho PRIVATE ${TEST_DEPS} wolfssl)
```

# Install / Build
### Build and install wolfSSL
```bash
git clone https://github.com/wolfSSL/wolfssl.git
```
```bash
cd wolfssl
```
```bash
./autogen.sh
```
```bash
./configure \
  --prefix="$HOME/local/wolfssl-mlkem-neon" \
  --enable-mlkem=yes,cache-a \
  --enable-dilithium \
  --enable-all-asm \
  --enable-cryptonly \
  --disable-shared \
  CFLAGS="-O3 -mcpu=apple-m1"
```
```bash
make -j"$(sysctl -n hw.ncpu)"
```
```bash
make install
```

### Build and install liboqs
```bash
brew install cmake ninja openssl@3 wget doxygen graphviz astyle valgrind
pip3 install pytest pytest-xdist pyyaml
```
```bash
git clone -b main https://github.com/open-quantum-safe/liboqs.git
```
```bash
cd liboqs
```
```bash
mkdir build && cd build
```
```bash
cmake .. -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$HOME/local/wolfssl-mlkem-neon" \
  -DCMAKE_C_FLAGS="-O3 -mcpu=apple-m1 -I$HOME/local/wolfssl-mlkem-neon/include" \
  -DCMAKE_EXE_LINKER_FLAGS="-L$HOME/local/wolfssl-mlkem-neon/lib"
```
```bash
ninja
```

If the build fails, verify that liboqs is linking against the installed wolfSSL on your system

# Run
```bash
./tests/example_kem_cho
```

# Author
ZHANG JIAXIAO

# License
MIT
