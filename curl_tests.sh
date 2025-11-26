#!/bin/bash
# Simple curl test script for jester-jr
# Run this after starting backend server and jester-jr manually
#
# Usage:
# 1. Start backend: python3 ./backend_server.py
# 2. Start jester-jr: ./target/debug/jester-jr working-test.toml
# 3. Run tests: ./curl_tests.sh

echo "🧪 Jester Jr Curl Test Suite"
echo "=============================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function test_request() {
    local test_name="$1"
    local curl_cmd="$2"
    local expected_pattern="$3"
    
    echo -n "Testing $test_name: "
    
    local output
    output=$(eval "$curl_cmd" 2>/dev/null)
    local exit_code=$?
    
    if [ $exit_code -eq 0 ] && [[ "$output" =~ $expected_pattern ]]; then
        echo -e "${GREEN}✅ PASS${NC}"
    else
        echo -e "${RED}❌ FAIL${NC}"
        echo "   Command: $curl_cmd"
        echo "   Output: $output"
        echo "   Exit code: $exit_code"
    fi
    echo ""
}

echo "📋 Testing basic connectivity..."
# Test 1: Health check (no auth required)
test_request "Health check" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' http://127.0.0.1:8090/health" \
    "Hello.*backend"

# Test 2: Basic request (catch-all route)
test_request "Basic request" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' http://127.0.0.1:8090/test" \
    "Hello.*backend"

echo "🔑 Testing API Key authentication..."
# Test 3: Valid API key
test_request "Valid API key" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' -H 'x-api-key: test-key-123' http://127.0.0.1:8090/api/public/users" \
    "Hello.*backend"

# Test 4: Invalid API key
test_request "Invalid API key (should fail)" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' -H 'x-api-key: invalid-key' http://127.0.0.1:8090/api/public/users" \
    "Unauthorized|Forbidden|Invalid|denied"

# Test 5: Missing API key
test_request "Missing API key (should fail)" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' http://127.0.0.1:8090/api/public/users" \
    "Unauthorized|Forbidden|Missing|denied"

echo "🔒 Testing Jester-Secret authentication..."
# Test 6: Valid Jester-Secret
test_request "Valid Jester-Secret" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' http://127.0.0.1:8090/api/secure/data" \
    "Hello.*backend"

# Test 7: Invalid Jester-Secret (commenting out to avoid blacklisting)
# test_request "Invalid Jester-Secret (should fail)" \
#     "curl -v -H 'jester-secret: wrong-secret' http://127.0.0.1:8090/api/secure/data" \
#     "Unauthorized|Forbidden|Invalid|denied"

# Test 8: Missing Jester-Secret (commenting out to avoid blacklisting)  
# test_request "Missing Jester-Secret (should fail)" \
#     "curl -v http://127.0.0.1:8090/api/secure/data" \
#     "Unauthorized|Forbidden|Missing|denied"

echo "🌐 Testing HTTP methods..."
# Test 9: POST request
test_request "POST request" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' -X POST -d 'test data' http://127.0.0.1:8090/test" \
    "Hello.*backend"

# Test 10: PUT request
test_request "PUT request" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' -X PUT -d 'test data' http://127.0.0.1:8090/test" \
    "Hello.*backend"

# Test 11: PATCH request
test_request "PATCH request" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' -X PATCH -d 'test data' http://127.0.0.1:8090/test" \
    "Hello.*backend"

echo "🚫 Testing blocked requests..."
# Test 12: DELETE method (should be blocked by global rules)
test_request "DELETE method (should fail)" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' -X DELETE http://127.0.0.1:8090/test" \
    "Method.*not.*allowed|Forbidden|denied"

# Test 13: TRACE method (should be blocked)
test_request "TRACE method (should fail)" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' -X TRACE http://127.0.0.1:8090/test" \
    "Method.*not.*allowed|Forbidden|denied"

echo "📏 Testing path routing..."
# Test 14: Path with API key and prefix stripping
test_request "Path prefix stripping" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' -H 'x-api-key: test-key-123' http://127.0.0.1:8090/api/public/users/123" \
    "Hello.*backend"

# Test 15: Jester-Secret with path stripping
test_request "Secure path prefix stripping" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' http://127.0.0.1:8090/api/secure/admin/settings" \
    "Hello.*backend"

echo "🔍 Testing verbose requests (with headers)..."
# Test 16: Check response headers
echo -n "Response headers check: "
headers=$(curl -v -I -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' http://127.0.0.1:8090/health 2>/dev/null)
if ([[ "$headers" =~ "HTTP/1.1 200" ]] || [[ "$headers" =~ "HTTP/1.0 200" ]]) && [[ "$headers" =~ "Content-Type" ]]; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    echo "   Headers: $headers"
fi
echo ""

# Test 17: Request with custom headers
test_request "Custom headers forwarding" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' -H 'X-Custom-Header: test-value' http://127.0.0.1:8090/test" \
    "Hello.*backend"

echo "⚡ Testing edge cases..."
# Test 18: Very long path
test_request "Long path handling" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' http://127.0.0.1:8090/very/long/path/with/many/segments/to/test/routing" \
    "Hello.*backend"

# Test 19: Query parameters
test_request "Query parameters" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' 'http://127.0.0.1:8090/test?param1=value1&param2=value2'" \
    "Hello.*backend"

# Test 20: URL encoded path
test_request "URL encoded path" \
    "curl -v -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' 'http://127.0.0.1:8090/test%20with%20spaces'" \
    "Hello.*backend"

echo "✅ Test suite completed!"
echo ""
echo "💡 Expected behavior:"
echo "   - Health and basic requests should work (catch-all route)"
echo "   - API key routes require valid x-api-key header"
echo "   - Secure routes require valid jester-secret header"
echo "   - Invalid auth should return 401/403 errors"
echo "   - Dangerous methods (DELETE, TRACE) should be blocked"
echo ""
echo "📊 To see detailed logs, check jester-jr console output"