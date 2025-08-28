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

echo "3. Basic analysis of /bin/ls (queries API automatically):"
$WATC analyze /bin/ls
echo

echo "4. Verbose analysis with detailed information (shows API queries):"
$WATC analyze /bin/ls --verbose
echo

echo "5. JSON output for programmatic use (includes API results):"
$WATC analyze /bin/ls --format json
echo

echo "6. JSON output saved to file (with API detection results):"
$WATC analyze /bin/ls --json-file
echo

echo "7. Simple text output:"
$WATC analyze /bin/ls --format simple
echo

echo "8. CSV output:"
$WATC analyze /bin/ls --format csv
echo

echo "9. Analysis with symbol statistics:"
$WATC analyze /bin/ls --show-stats
echo

echo "10. Test API connectivity (this will try to connect to libc.rip):"
$WATC test-api
echo

# Analyze a few more binaries if available
for binary in /bin/cat /usr/bin/curl /bin/bash; do
    if [ -f "$binary" ]; then
        echo "11. Quick analysis of $binary:"
        $WATC analyze "$binary" --format simple
        echo
    fi
done

echo "=== Examples Complete ==="
echo
echo "Try these commands yourself:"
echo "  $WATC analyze <binary_path>                    # Basic analysis with API query"
echo "  $WATC analyze <binary_path> --verbose          # Detailed analysis with API details"
echo "  $WATC analyze <binary_path> --format json      # JSON output with API results"
echo "  $WATC analyze <binary_path> --json-file        # Save complete JSON to file"
echo "  $WATC tools                                    # Check external tools"
echo "  $WATC test-api                                 # Test API connection"
