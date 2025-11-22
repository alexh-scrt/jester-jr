#!/bin/bash
# Test script for Jester Jr TLS support
#
# Tests both HTTP and HTTPS modes with various scenarios

set -e

echo "🃏 Jester Jr TLS Test Suite 🃏"
echo "=============================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print test results
pass() {
    echo -e "${GREEN}✓${NC} $1"
}

fail() {
    echo -e "${RED}✗${NC} $1"
}

info() {
    echo -e "${YELLOW}→${NC} $1"
}

# Check if backend is running
check_backend() {
    if ! curl -s http://localhost:9090 > /dev/null 2>&1; then
        echo "❌ Backend server not running on port 9090"
        echo "   Start it with: python3 backend_server.py"
        exit 1
    fi
    pass "Backend server is running"
}

# Check if proxy is running
check_proxy() {
    local port=$1
    local protocol=$2
    
    if [ "$protocol" = "https" ]; then
        if curl -k -s https://localhost:$port > /dev/null 2>&1; then
            pass "Proxy is running on $protocol://localhost:$port"
            return 0
        fi
    else
        if curl -s http://localhost:$port > /dev/null 2>&1; then
            pass "Proxy is running on $protocol://localhost:$port"
            return 0
        fi
    fi
    
    fail "Proxy is not running on $protocol://localhost:$port"
    return 1
}

# Test HTTP request
test_http() {
    local url=$1
    local expected_code=$2
    local description=$3
    
    info "Testing: $description"
    
    local response_code=$(curl -k -s -o /dev/null -w "%{http_code}" "$url")
    
    if [ "$response_code" = "$expected_code" ]; then
        pass "Got expected status code $expected_code"
    else
        fail "Expected $expected_code but got $response_code"
        return 1
    fi
}

# Test TLS handshake
test_tls_handshake() {
    info "Testing TLS handshake..."
    
    local output=$(curl -kv https://localhost:8443/ 2>&1)
    
    if echo "$output" | grep -q "SSL connection using"; then
        local cipher=$(echo "$output" | grep "SSL connection using" | head -1)
        pass "TLS handshake successful"
        echo "   $cipher"
    else
        fail "TLS handshake failed"
        return 1
    fi
}

# Test TLS version
test_tls_version() {
    info "Testing TLS version support..."
    
    # Test TLS 1.2
    if curl -k --tlsv1.2 --tls-max 1.2 -s https://localhost:8443/ > /dev/null 2>&1; then
        pass "TLS 1.2 supported"
    else
        fail "TLS 1.2 not supported"
    fi
    
    # Test TLS 1.3
    if curl -k --tlsv1.3 -s https://localhost:8443/ > /dev/null 2>&1; then
        pass "TLS 1.3 supported"
    else
        info "TLS 1.3 not supported (may not be available on this system)"
    fi
}

# Main test execution
main() {
    echo "📋 Pre-flight checks:"
    check_backend
    echo ""
    
    # Determine which mode to test
    if check_proxy 8443 "https"; then
        echo ""
        echo "🔒 Testing HTTPS Mode"
        echo "====================="
        echo ""
        
        # TLS-specific tests
        test_tls_handshake
        echo ""
        
        test_tls_version
        echo ""
        
        # Standard functionality tests
        echo "📨 Testing Request Handling:"
        test_http "https://localhost:8443/api/users" "200" "Normal API request"
        test_http "https://localhost:8443/admin/users" "403" "Blocked admin path"
        test_http "https://localhost:8443/protected/data" "403" "Protected path without auth"
        echo ""
        
        # Test with auth header
        info "Testing protected path with auth..."
        local response_code=$(curl -k -s -H "Authorization: Bearer token" -o /dev/null -w "%{http_code}" "https://localhost:8443/protected/data")
        if [ "$response_code" = "200" ]; then
            pass "Got expected status code 200 with auth header"
        else
            fail "Expected 200 but got $response_code"
        fi
        echo ""
        
    elif check_proxy 8080 "http"; then
        echo ""
        echo "🔓 Testing HTTP Mode"
        echo "===================="
        echo ""
        
        echo "📨 Testing Request Handling:"
        test_http "http://localhost:8080/api/users" "200" "Normal API request"
        test_http "http://localhost:8080/admin/users" "403" "Blocked admin path"
        test_http "http://localhost:8080/protected/data" "403" "Protected path without auth"
        echo ""
        
    else
        echo "❌ No proxy detected on port 8080 or 8443"
        echo "   Start it with: ./target/release/jester-jr [config.toml]"
        exit 1
    fi
    
    echo "✅ All tests completed!"
}

# Run tests
main