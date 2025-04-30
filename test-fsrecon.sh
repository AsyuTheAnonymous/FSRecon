#!/usr/bin/env bash
# Simple test script for FSRecon modules

echo "=== FSRecon Module Test Script ==="
echo "This script will test all modules using a direct approach"

# Source the core and logging systems
source ./lib/core.sh 
source ./lib/logger.sh

# Basic setup
DOMAIN="silvea.tech"
OUTPUT_DIR="./output/last_run"
mkdir -p "$OUTPUT_DIR"

echo "Testing domain: $DOMAIN"
echo "Output directory: $OUTPUT_DIR"

# Create targets file
mkdir -p "$OUTPUT_DIR/targets"
echo "$DOMAIN" > "$OUTPUT_DIR/targets/all_targets.txt"
echo "Created targets file with $DOMAIN"

# Load all modules manually
echo "Loading modules..."
for module in ./modules/*/main.sh; do
    echo "Loading module: $module"
    source "$module"
done

# Test subdomain enumeration
echo "=== Testing Subdomain Enumeration ==="
if declare -F "subdomain_scan" > /dev/null; then
    echo "Found subdomain_scan function, executing..."
    subdomain_scan "$DOMAIN" "$OUTPUT_DIR/subdomain" || echo "Failed with code $?"
    ls -la "$OUTPUT_DIR/subdomain" || echo "No output directory created"
else
    echo "ERROR: subdomain_scan function not found"
fi

# Test HTTP probing
echo "=== Testing HTTP Probing ==="
if declare -F "http_probe" > /dev/null; then
    echo "Found http_probe function, executing..."
    http_probe "$OUTPUT_DIR/targets/all_targets.txt" "$OUTPUT_DIR/http" || echo "Failed with code $?"
    ls -la "$OUTPUT_DIR/http" || echo "No output directory created"
else
    echo "ERROR: http_probe function not found"
fi

# Test port scanning
echo "=== Testing Port Scanning ==="
if declare -F "port_scan" > /dev/null; then
    echo "Found port_scan function, executing..."
    port_scan "$DOMAIN" "$OUTPUT_DIR/port" || echo "Failed with code $?"
    ls -la "$OUTPUT_DIR/port" || echo "No output directory created"
else
    echo "ERROR: port_scan function not found"
fi

echo "All tests completed. Check $OUTPUT_DIR for any results."
