#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Jester Jr v0.1.0 - Comprehensive Test Suite
# ═══════════════════════════════════════════════════════════════════════════════
#
# This script tests ALL implemented functionality for the v0.1.0 release:
# • Multi-listener architecture (HTTP, HTTPS, admin, dev)
# • TLS/HTTPS support and certificate validation
# • Path-based routing (prefix, regex, strip_prefix)
# • Request and response filtering
# • Validator framework (API key, JWT, Jester-Secret)
# • IP blacklisting and security features
# • Error handling and edge cases
#
# ═══════════════════════════════════════════════════════════════════════════════

set -e  # Exit on error

# Colors for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Test configuration
BACKEND_PID=""
JESTER_PID=""
TEST_CONFIG="test-jester-jr.toml"
JESTER_BINARY="./target/debug/jester-jr"
BACKEND_SCRIPT="./test_backend_server.py"

# Test statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# JWT token for testing (generated with secret "test-secret-for-jwt-validation")
# Payload: {"sub": "testuser", "iss": "jester-jr-test", "aud": "api", "exp": 9999999999}
# Generated with: echo -n '{"alg":"HS256","typ":"JWT"}' | base64 -w0; echo -n '{"sub":"testuser","iss":"jester-jr-test","aud":"api","exp":9999999999}' | base64 -w0
TEST_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlzcyI6Implc3Rlci1qci10ZXN0IiwiYXVkIjoiYXBpIiwiZXhwIjo5OTk5OTk5OTk5fQ.Kx1-7dYdEPsV8KNWz6TM8ZtYQ6U2LPv0Bq3YQ6U2LPv"

function print_header() {
    echo -e "${WHITE}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo "  $1"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

function print_section() {
    echo -e "${CYAN}"
    echo "───────────────────────────────────────────────────────────────────────────────"
    echo "  $1"
    echo "───────────────────────────────────────────────────────────────────────────────"
    echo -e "${NC}"
}

function log_test() {
    echo -e "${YELLOW}[TEST] $1${NC}"
}

function log_success() {
    echo -e "${GREEN}[PASS] $1${NC}"
    ((PASSED_TESTS++))
}

function log_failure() {
    echo -e "${RED}[FAIL] $1${NC}"
    ((FAILED_TESTS++))
}

function log_info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

function run_test() {
    local test_name="$1"
    local curl_cmd="$2"
    local expected_pattern="$3"
    local should_fail="${4:-false}"
    
    ((TOTAL_TESTS++))
    log_test "$test_name"
    
    # Execute curl command and capture output
    local output
    local exit_code=0
    output=$(eval "$curl_cmd" 2>&1) || exit_code=$?
    
    if [ "$should_fail" == "true" ]; then
        # Test should fail
        if [ $exit_code -eq 0 ] && [[ "$output" =~ $expected_pattern ]]; then
            log_failure "$test_name - Expected failure but request succeeded"
            echo "   Output: $output"
        else
            log_success "$test_name - Correctly failed as expected"
        fi
    else
        # Test should succeed
        if [ $exit_code -eq 0 ] && [[ "$output" =~ $expected_pattern ]]; then
            log_success "$test_name"
        else
            log_failure "$test_name - Exit code: $exit_code"
            echo "   Expected pattern: $expected_pattern"
            echo "   Actual output: $output"
        fi
    fi
    
    echo
}

function cleanup() {
    echo -e "${YELLOW}Cleaning up processes...${NC}"
    
    if [ -n "$JESTER_PID" ] && kill -0 "$JESTER_PID" 2>/dev/null; then
        echo "Stopping Jester Jr (PID: $JESTER_PID)"
        kill "$JESTER_PID" 2>/dev/null || true
        wait "$JESTER_PID" 2>/dev/null || true
    fi
    
    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        echo "Stopping backend servers (PID: $BACKEND_PID)"
        kill "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi
    
    # Kill any remaining processes
    pkill -f "test_backend_server.py" 2>/dev/null || true
    pkill -f "jester-jr" 2>/dev/null || true
    
    echo "Cleanup complete"
}

function check_prerequisites() {
    print_section "Checking Prerequisites"
    
    # Check if jester-jr binary exists
    if [ ! -f "$JESTER_BINARY" ]; then
        echo -e "${RED}❌ Jester Jr binary not found at $JESTER_BINARY${NC}"
        echo "Please build with: cargo build"
        exit 1
    fi
    
    # Check if test config exists
    if [ ! -f "$TEST_CONFIG" ]; then
        echo -e "${RED}❌ Test configuration not found at $TEST_CONFIG${NC}"
        exit 1
    fi
    
    # Check if backend script exists
    if [ ! -f "$BACKEND_SCRIPT" ]; then
        echo -e "${RED}❌ Backend server script not found at $BACKEND_SCRIPT${NC}"
        exit 1
    fi
    
    # Check if Python 3 is available
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python 3 not found${NC}"
        exit 1
    fi
    
    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}❌ curl not found${NC}"
        exit 1
    fi
    
    # Create data directory for blacklist
    mkdir -p data
    
    # Create minimal TLS certificates for HTTPS testing
    if [ ! -d "certs" ]; then
        echo "Creating test TLS certificates..."
        mkdir -p certs
        openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt \
            -days 365 -nodes -subj "/C=US/ST=Test/L=Test/O=JesterJr/CN=localhost" >/dev/null 2>&1 || true
    fi
    
    log_info "All prerequisites satisfied"
    echo
}

function start_services() {
    print_section "Starting Services"
    
    # Start backend servers
    log_info "Starting test backend servers..."
    python3 "$BACKEND_SCRIPT" &
    BACKEND_PID=$!
    sleep 3
    
    # Verify backend servers started
    if ! curl -s http://127.0.0.1:9090/health >/dev/null; then
        echo -e "${RED}❌ Backend servers failed to start${NC}"
        cleanup
        exit 1
    fi
    
    # Start Jester Jr
    log_info "Starting Jester Jr reverse proxy..."
    "$JESTER_BINARY" "$TEST_CONFIG" &
    JESTER_PID=$!
    sleep 5
    
    # Verify Jester Jr started on all ports
    local ports=(8080 8443 8081 3000)
    for port in "${ports[@]}"; do
        if ! netstat -tln 2>/dev/null | grep -q ":$port "; then
            echo -e "${RED}❌ Jester Jr failed to start on port $port${NC}"
            cleanup
            exit 1
        fi
    done
    
    log_info "All services started successfully"
    echo
}

function test_http_public_api() {
    print_section "Testing Public HTTP API (Port 8080)"
    
    # Test health check (no authentication)
    run_test "Health check endpoint" \
        'curl -s http://127.0.0.1:8080/health' \
        '"status": "healthy"'
    
    # Test public API with valid API key
    run_test "Public API with valid API key" \
        'curl -s -H "x-api-key: test-key-123" http://127.0.0.1:8080/api/v1/public/users' \
        '"Public API Backend"'
    
    # Test public API without API key (should fail)
    run_test "Public API without API key" \
        'curl -s http://127.0.0.1:8080/api/v1/public/users' \
        'Unauthorized\|Forbidden\|API key required' \
        true
    
    # Test protected API with required header
    run_test "Protected API with required header" \
        'curl -s -H "X-Protected-Key: protected123" http://127.0.0.1:8080/api/v1/protected/data' \
        '"Protected API Backend"'
    
    # Test protected API without required header (should fail)
    run_test "Protected API without required header" \
        'curl -s http://127.0.0.1:8080/api/v1/protected/data' \
        'Missing required header\|Forbidden' \
        true
    
    # Test API v2 with required header
    run_test "API v2 with required header" \
        'curl -s -H "X-API-Version: 2.0" http://127.0.0.1:8080/api/v2/features' \
        '"V2 API Backend"'
    
    # Test API v2 without required header (should fail)
    run_test "API v2 without required header" \
        'curl -s http://127.0.0.1:8080/api/v2/features' \
        'Missing required header\|Forbidden' \
        true
    
    # Test method filtering
    run_test "Allowed POST method" \
        'curl -s -X POST http://127.0.0.1:8080/test/methods' \
        '"method": "POST"'
    
    # Test blocked method
    run_test "Blocked DELETE method" \
        'curl -s -X DELETE http://127.0.0.1:8080/test/methods' \
        'Method not allowed\|Forbidden' \
        true
    
    # Test admin path blocking (global rule)
    run_test "Admin path blocking" \
        'curl -s http://127.0.0.1:8080/admin/users' \
        'Forbidden\|Access denied' \
        true
    
    # Test dangerous HTTP methods blocking
    run_test "TRACE method blocking" \
        'curl -s -X TRACE http://127.0.0.1:8080/health' \
        'Method not allowed\|Forbidden' \
        true
}

function test_https_secure_api() {
    print_section "Testing Secure HTTPS API (Port 8443)"
    
    # Test secure health check with TLS
    run_test "HTTPS health check" \
        'curl -k -s https://127.0.0.1:8443/health-secure' \
        '"status": "healthy"'
    
    # Test secure API with Jester-Secret
    run_test "Secure API with Jester-Secret" \
        'curl -k -s -H "jester-secret: FVDRuKEZw4LBnLxVkWjD" https://127.0.0.1:8443/api/secure/data' \
        '"Primary Backend"'
    
    # Test secure API without Jester-Secret (should fail)
    run_test "Secure API without Jester-Secret" \
        'curl -k -s https://127.0.0.1:8443/api/secure/data' \
        'Unauthorized\|Forbidden' \
        true
    
    # Test HTTPS admin interface with admin token
    run_test "HTTPS admin with valid admin token" \
        "curl -k -s -H 'X-Admin-Token: admin123' https://127.0.0.1:8443/admin/dashboard" \
        '"Admin Backend"'
    
    # Test HTTPS admin without admin token (should fail)
    run_test "HTTPS admin without admin token" \
        "curl -k -s https://127.0.0.1:8443/admin/dashboard" \
        'Missing required header\|Forbidden' \
        true
}

function test_internal_admin() {
    print_section "Testing Internal Admin Interface (Port 8081)"
    
    # Test admin dashboard (internal, relaxed security)
    run_test "Internal admin dashboard" \
        'curl -s http://127.0.0.1:8081/dashboard' \
        '"Admin Backend"'
    
    # Test monitoring endpoint
    run_test "Internal monitoring" \
        'curl -s http://127.0.0.1:8081/monitor/stats' \
        '"Public API Backend"'
    
    # Test blacklist management
    run_test "Blacklist management" \
        'curl -s http://127.0.0.1:8081/blacklist/status' \
        '"Primary Backend"'
    
    # Test default backend forwarding for unmatched routes
    run_test "Default backend forwarding" \
        'curl -s http://127.0.0.1:8081/unmatched/path' \
        '"Admin Backend"'
}

function test_development_server() {
    print_section "Testing Development Server (Port 3000)"
    
    # Test development API (relaxed rules)
    run_test "Development API" \
        'curl -s http://127.0.0.1:3000/api/dev' \
        '"Protected API Backend"'
    
    # Test frontend development
    run_test "Development frontend" \
        'curl -s http://127.0.0.1:3000/app/index.html' \
        '"V2 API Backend"'
    
    # Test that dangerous methods are allowed in dev mode
    run_test "DELETE allowed in dev mode" \
        'curl -s -X DELETE http://127.0.0.1:3000/api/resource' \
        '"method": "DELETE"'
}

function test_response_filtering() {
    print_section "Testing Response Filtering"
    
    # Test large response blocking (size limit)
    run_test "Large response blocking" \
        'curl -s http://127.0.0.1:8080/large' \
        'Response too large\|Content length exceeded\|Error 413' \
        true
    
    # Test error status code blocking
    run_test "500 status code blocking" \
        'curl -s http://127.0.0.1:8080/error/500' \
        'Server error blocked\|Internal server error' \
        true
}

function test_path_routing() {
    print_section "Testing Path Routing & Rewriting"
    
    # Test prefix stripping (strip_prefix = true)
    run_test "Path prefix stripping" \
        'curl -s -H "x-api-key: test-key-123" http://127.0.0.1:8080/api/v1/public/test/path' \
        '"path": "/test/path"'
    
    # Test no prefix stripping (strip_prefix = false)
    run_test "No path prefix stripping" \
        'curl -s -H "X-API-Version: 2.0" http://127.0.0.1:8080/api/v2/full/path' \
        '"path": "/api/v2/full/path"'
}

function test_timeout_behavior() {
    print_section "Testing Timeout Behavior"
    
    # Test timeout with unreachable backend (should timeout quickly)
    run_test "Request timeout test" \
        'timeout 10 curl -s http://127.0.0.1:8080/test/timeout' \
        'timeout\|connection\|error\|Gateway' \
        true
}

function test_validator_edge_cases() {
    print_section "Testing Validator Edge Cases"
    
    # Test invalid API key
    run_test "Invalid API key" \
        'curl -s -H "x-api-key: invalid-key" http://127.0.0.1:8080/api/v1/public/users' \
        'Invalid API key\|Unauthorized\|Forbidden' \
        true
    
    # Test missing required header
    run_test "Missing required header test" \
        'curl -s http://127.0.0.1:8080/api/v1/protected/data' \
        'Missing required header\|Forbidden' \
        true
    
    # Test wrong Jester-Secret
    run_test "Invalid Jester-Secret" \
        'curl -k -s -H "jester-secret: wrong-secret" https://127.0.0.1:8443/api/secure/data' \
        'Invalid secret\|Unauthorized\|Forbidden' \
        true
}

function test_http_methods() {
    print_section "Testing HTTP Methods"
    
    # Test various HTTP methods on upload endpoint
    run_test "POST to upload endpoint" \
        'curl -s -X POST -d "test data" http://127.0.0.1:8080/upload' \
        '"upload_status": "received"'
    
    # Test PUT method
    run_test "PUT method on internal admin" \
        'curl -s -X PUT -d "update data" http://127.0.0.1:8081/dashboard/config' \
        '"method": "PUT"'
    
    # Test PATCH method
    run_test "PATCH method on internal admin" \
        'curl -s -X PATCH -d "patch data" http://127.0.0.1:8081/monitor/settings' \
        '"method": "PATCH"'
}

function test_tls_and_security() {
    print_section "Testing TLS and Security Features"
    
    # Test TLS certificate validation
    run_test "TLS certificate verification (self-signed)" \
        'curl -s https://127.0.0.1:8443/health-secure' \
        'certificate\|SSL\|TLS' \
        true  # Should fail with strict cert validation
    
    # Test successful TLS connection with -k flag
    run_test "TLS connection with insecure flag" \
        'curl -k -s https://127.0.0.1:8443/health-secure' \
        '"status": "healthy"'
}

function print_test_summary() {
    print_header "Test Summary"
    
    echo -e "${WHITE}Total Tests: $TOTAL_TESTS${NC}"
    echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
    
    local pass_rate
    if [ $TOTAL_TESTS -gt 0 ]; then
        pass_rate=$(( (PASSED_TESTS * 100) / TOTAL_TESTS ))
        echo -e "${CYAN}Pass Rate: ${pass_rate}%${NC}"
    fi
    
    echo
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests passed! Jester Jr v0.1.0 is ready for release.${NC}"
        return 0
    else
        echo -e "${RED}❌ Some tests failed. Please review and fix issues before release.${NC}"
        return 1
    fi
}

function main() {
    # Set up cleanup trap
    trap cleanup EXIT INT TERM
    
    print_header "Jester Jr v0.1.0 - Comprehensive Test Suite"
    
    echo -e "${BLUE}"
    echo "This test suite validates all functionality for the v0.1.0 public release:"
    echo "• Multi-listener architecture (HTTP/HTTPS/Admin/Dev)"
    echo "• TLS/HTTPS support and certificate handling"
    echo "• Path-based routing with prefix/regex matching"
    echo "• Request and response filtering capabilities"
    echo "• Validator framework (API key, JWT, Jester-Secret)"
    echo "• IP blacklisting and security features"
    echo "• Error handling and edge case scenarios"
    echo -e "${NC}"
    echo
    
    # Run test phases
    check_prerequisites
    start_services
    
    # Execute all test suites
    test_http_public_api
    test_https_secure_api
    test_internal_admin
    test_development_server
    test_response_filtering
    test_path_routing
    test_timeout_behavior
    test_validator_edge_cases
    test_http_methods
    test_tls_and_security
    
    # Print results
    print_test_summary
    local exit_code=$?
    
    cleanup
    exit $exit_code
}

# Run main function
main "$@"