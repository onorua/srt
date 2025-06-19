#!/bin/bash

# Simple build script to test our Reed-Solomon FEC implementation
# This assumes you have the libfec library installed

echo "Building Reed-Solomon FEC test..."

# Check if libfec is available
if ! pkg-config --exists fec 2>/dev/null; then
    echo "Warning: libfec not found via pkg-config"
    echo "Trying to compile with -lfec..."
    LIBFEC_FLAGS="-lfec"
else
    echo "Found libfec via pkg-config"
    LIBFEC_FLAGS="$(pkg-config --cflags --libs fec)"
fi

# Compile the test
g++ -std=c++17 -O2 -Wall -Wextra \
    test_fec_rs_basic.cpp \
    $LIBFEC_FLAGS \
    -o test_fec_rs_basic

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "Running test..."
    echo ""
    ./test_fec_rs_basic
else
    echo "Build failed!"
    echo ""
    echo "If libfec is not installed, you can install it on Ubuntu/Debian with:"
    echo "  sudo apt-get install libfec-dev"
    echo ""
    echo "Or on CentOS/RHEL with:"
    echo "  sudo yum install libfec-devel"
    echo ""
    echo "Or build from source:"
    echo "  git clone https://github.com/quiet/libfec"
    echo "  cd libfec"
    echo "  ./configure && make && sudo make install"
    exit 1
fi
