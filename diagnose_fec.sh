#!/bin/bash

echo "=== SRT Reed-Solomon FEC Diagnostic Script ==="
echo ""

# Check if SRT tools exist
echo "1. Checking SRT tools..."
if command -v srt-live-transmit >/dev/null 2>&1; then
    echo "✓ srt-live-transmit found: $(which srt-live-transmit)"
    SRT_VERSION=$(srt-live-transmit --version 2>&1 | head -1)
    echo "  Version: $SRT_VERSION"
else
    echo "✗ srt-live-transmit not found"
fi

if command -v srt-ffplay >/dev/null 2>&1; then
    echo "✓ srt-ffplay found: $(which srt-ffplay)"
else
    echo "✗ srt-ffplay not found"
fi

echo ""

# Check for Reed-Solomon library
echo "2. Checking Reed-Solomon library (libfec)..."
if ldconfig -p 2>/dev/null | grep -q libfec; then
    echo "✓ libfec found in system libraries:"
    ldconfig -p | grep libfec
elif find /usr -name "*libfec*" -type f 2>/dev/null | head -3 | grep -q .; then
    echo "✓ libfec files found:"
    find /usr -name "*libfec*" -type f 2>/dev/null | head -3
else
    echo "✗ libfec not found"
    echo "  Install with:"
    echo "    Ubuntu/Debian: sudo apt-get install libfec-dev"
    echo "    CentOS/RHEL:   sudo yum install libfec-devel"
    echo "    Or build from: https://github.com/quiet/libfec"
fi

echo ""

# Check if SRT was built with FEC support
echo "3. Checking SRT FEC support..."
if command -v srt-live-transmit >/dev/null 2>&1; then
    # Check if FEC symbols are in the binary
    if strings $(which srt-live-transmit) 2>/dev/null | grep -q "rsfec\|fec"; then
        echo "✓ FEC support appears to be compiled in"
        echo "  FEC-related strings found:"
        strings $(which srt-live-transmit) 2>/dev/null | grep -i fec | head -3
    else
        echo "✗ No FEC support found in binary"
        echo "  SRT may not be compiled with ENABLE_RSFEC=ON"
    fi
    
    # Check library dependencies
    echo ""
    echo "  Library dependencies:"
    if ldd $(which srt-live-transmit) 2>/dev/null | grep -q fec; then
        echo "✓ libfec linked:"
        ldd $(which srt-live-transmit) | grep fec
    else
        echo "✗ libfec not linked"
    fi
else
    echo "✗ Cannot check - srt-live-transmit not found"
fi

echo ""

# Test basic SRT functionality
echo "4. Testing basic SRT functionality..."
echo "  Testing SRT help for packet filter options:"
if srt-live-transmit --help 2>&1 | grep -q "packetfilter\|filter"; then
    echo "✓ Packet filter options found in help"
else
    echo "✗ No packet filter options in help"
fi

echo ""

# Check for our implementation files
echo "5. Checking our Reed-Solomon implementation..."
if [ -f "srtcore/fec_rs.h" ] && [ -f "srtcore/fec_rs.cpp" ]; then
    echo "✓ Reed-Solomon FEC files present"
    echo "  srtcore/fec_rs.h: $(wc -l < srtcore/fec_rs.h) lines"
    echo "  srtcore/fec_rs.cpp: $(wc -l < srtcore/fec_rs.cpp) lines"
else
    echo "✗ Reed-Solomon FEC files missing"
fi

echo ""

# Provide recommendations
echo "=== RECOMMENDATIONS ==="
echo ""

# Check what's missing
MISSING_LIBFEC=false
MISSING_SRT_FEC=false

if ! ldconfig -p 2>/dev/null | grep -q libfec && ! find /usr -name "*libfec*" -type f 2>/dev/null | head -1 | grep -q .; then
    MISSING_LIBFEC=true
fi

if command -v srt-live-transmit >/dev/null 2>&1; then
    if ! strings $(which srt-live-transmit) 2>/dev/null | grep -q "rsfec"; then
        MISSING_SRT_FEC=true
    fi
else
    MISSING_SRT_FEC=true
fi

if [ "$MISSING_LIBFEC" = true ]; then
    echo "1. INSTALL REED-SOLOMON LIBRARY:"
    echo "   Ubuntu/Debian: sudo apt-get install libfec-dev"
    echo "   CentOS/RHEL:   sudo yum install libfec-devel"
    echo "   From source:   git clone https://github.com/quiet/libfec"
    echo "                  cd libfec && ./configure && make && sudo make install"
    echo ""
fi

if [ "$MISSING_SRT_FEC" = true ]; then
    echo "2. REBUILD SRT WITH FEC SUPPORT:"
    echo "   mkdir build && cd build"
    echo "   cmake .. -DENABLE_RSFEC=ON"
    echo "   make -j\$(nproc)"
    echo "   sudo make install"
    echo ""
fi

if [ "$MISSING_LIBFEC" = false ] && [ "$MISSING_SRT_FEC" = false ]; then
    echo "✓ All dependencies appear to be present!"
    echo ""
    echo "If video still doesn't show, try:"
    echo "1. Test without FEC first:"
    echo "   Sender:   srt-live-transmit udp://:1234 srt://127.0.0.1:8890"
    echo "   Receiver: srt-ffplay srt://:8890"
    echo ""
    echo "2. Enable debug logging:"
    echo "   SRT_LOGLEVEL=debug srt-live-transmit ..."
    echo ""
    echo "3. Check if receiver supports packet filters:"
    echo "   Try: srt-live-transmit \"srt://:8890?packetfilter=rsfec,cols:5,rows:2\" udp://127.0.0.1:5000"
    echo "   Then: ffplay udp://127.0.0.1:5000"
fi

echo ""
echo "=== DIAGNOSTIC COMPLETE ==="
