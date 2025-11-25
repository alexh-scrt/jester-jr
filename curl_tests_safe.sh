#!/bin/bash
# Safe curl test script that avoids IP blacklisting issues
# Tests are ordered to minimize blacklisting impact

echo "🧪 Jester Jr Safe Test Suite"
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
    local should_fail="${4:-false}"
    
    echo -n "Testing $test_name: "
    
    local output
    output=$(eval "$curl_cmd" 2>/dev/null)
    local exit_code=$?
    
    if [ "$should_fail" == "true" ]; then
        # Test should fail
        if [ $exit_code -ne 0 ] || [[ "$output" =~ $expected_pattern ]]; then
            echo -e "${GREEN}✅ PASS (correctly failed)${NC}"
        else
            echo -e "${RED}❌ FAIL (should have failed)${NC}"
            echo "   Output: $output"
        fi
    else
        # Test should succeed
        if [ $exit_code -eq 0 ] && [[ "$output" =~ $expected_pattern ]]; then
            echo -e "${GREEN}✅ PASS${NC}"
        else
            echo -e "${RED}❌ FAIL${NC}"
            echo "   Command: $curl_cmd"
            echo "   Output: $output"
            echo "   Exit code: $exit_code"
        fi
    fi
    echo ""
}

echo "📋 Testing non-authenticated endpoints first..."

# Test 1: Health check (should always work)
test_request "Health check" \
    "curl -s http://127.0.0.1:8090/health" \
    "Hello.*backend"

# Test 2: Basic request (catch-all, should work)
test_request "Basic request" \
    "curl -s http://127.0.0.1:8090/test" \
    "Hello.*backend"

# Test 3: POST request (catch-all)
test_request "POST request" \
    "curl -s -X POST -d 'test data' http://127.0.0.1:8090/test" \
    "Hello.*backend"

echo "🔑 Testing API Key authentication (safer than Jester-Secret)..."

# Test 4: Valid API key
test_request "Valid API key" \
    "curl -s -H 'x-api-key: test-key-123' http://127.0.0.1:8090/api/public/users" \
    "Hello.*backend"

# Test 5: Valid API key with path
test_request "API key with path" \
    "curl -s -H 'x-api-key: test-key-123' http://127.0.0.1:8090/api/public/users/123" \
    "Hello.*backend"

echo "🚫 Testing blocked requests..."

# Test 6: Invalid API key (should fail gracefully)
test_request "Invalid API key" \
    "curl -s -H 'x-api-key: invalid-key' http://127.0.0.1:8090/api/public/users" \
    "Unauthorized|Forbidden|Invalid|denied" \
    true

# Test 7: Missing API key (should fail gracefully) 
test_request "Missing API key" \
    "curl -s http://127.0.0.1:8090/api/public/users" \
    "Unauthorized|Forbidden|Missing|denied" \
    true

# Test 8: DELETE method (should be blocked)
test_request "DELETE method" \
    "curl -s -X DELETE http://127.0.0.1:8090/test" \
    "Method.*not.*allowed|Forbidden|denied" \
    true

echo "🔒 Testing Jester-Secret (may cause IP blacklisting)..."

# Test 9: Valid Jester-Secret
test_request "Valid Jester-Secret" \
    "curl -s -H 'jester-secret: FVDRuKEZw4LBnLxVkWjD' http://127.0.0.1:8090/api/secure/data" \
    "Hello.*backend"

# Test 10: Invalid Jester-Secret (this may blacklist localhost)
test_request "Invalid Jester-Secret" \
    "curl -s -H 'jester-secret: wrong-secret' http://127.0.0.1:8090/api/secure/data" \
    "Unauthorized|Forbidden|Invalid|denied" \
    true

echo "⚡ Testing additional cases..."

# Test 11: Query parameters
test_request "Query parameters" \
    "curl -s 'http://127.0.0.1:8090/test?param1=value1&param2=value2'" \
    "Hello.*backend"

# Test 12: Custom headers
test_request "Custom headers" \
    "curl -s -H 'X-Custom-Header: test-value' http://127.0.0.1:8090/test" \
    "Hello.*backend"

echo "💡 Testing response headers..."
echo -n "Response headers check: "
headers=$(curl -s -I http://127.0.0.1:8090/health 2>/dev/null)
if [[ "$headers" =~ "HTTP/1.1 200" ]] && [[ "$headers" =~ "Content-Type" ]]; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    echo "   Headers: $headers"
fi
echo ""

echo "✅ Test suite completed!"
echo ""
echo "⚠️  NOTE: If localhost gets blacklisted during testing:"
echo "   1. Stop jester-jr" 
echo "   2. Clear test-blacklist.json: echo '{\"entries\":[]}' > test-blacklist.json"
echo "   3. Restart jester-jr and re-run tests"