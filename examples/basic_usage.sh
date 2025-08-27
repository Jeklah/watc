#!/bin/bash

# Basic Usage Examples for watc (What Are Those C libraries?)

set -e

echo "=== watc Basic Usage Examples ==="
echo

# Check if watc is available
if ! command -v ./target/release/watc &> /dev/null; then
    echo "Error: watc binary not found. Please build it first with 'cargo build --release'"
    exit 1
fi

WATC="./target/release/watc"

echo "1. Check tool availability:"
$WATC tools
echo

echo "2. Show supported formats:"
$WATC formats
echo

echo "3. Basic analysis of /bin/ls (offline mode):"
$WATC analyze /bin/ls --offline
echo

echo "4. Verbose analysis with detailed information:"
$WATC analyze /bin/ls --offline --verbose
echo

echo "5. JSON output for programmatic use:"
$WATC analyze /bin/ls --offline --format json | head -20
echo "... (truncated for brevity)"
echo

echo "6. Simple text output:"
$WATC analyze /bin/ls --offline --format simple
echo

echo "7. CSV output:"
$WATC analyze /bin/ls --offline --format csv
echo

echo "8. Analysis with symbol statistics:"
$WATC analyze /bin/ls --offline --show-stats
echo

echo "9. Test API connectivity (this will try to connect to libc.blukat.me):"
$WATC test-api || echo "API test failed - this is normal if offline"
echo

# Analyze a few more binaries if available
for binary in /bin/cat /usr/bin/curl /bin/bash; do
    if [ -f "$binary" ]; then
        echo "10. Quick analysis of $binary:"
        $WATC analyze "$binary" --offline --format simple
        echo
    fi
done

echo "=== Examples Complete ==="
echo
echo "Try these commands yourself:"
echo "  $WATC analyze <binary_path>                    # Basic analysis"
echo "  $WATC analyze <binary_path> --verbose          # Detailed analysis"
echo "  $WATC analyze <binary_path> --format json      # JSON output"
echo "  $WATC analyze <binary_path> --offline          # Skip online queries"
echo "  $WATC tools                                     # Check external tools"
echo "  $WATC test-api                                  # Test API connection"
