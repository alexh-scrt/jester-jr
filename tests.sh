#!/bin/bash
# Start backend server
python3 backend_server.py &
BACKEND_PID=$!
sleep 1

# Start Jester Jr with config
./target/debug/jester-jr jester-jr.toml &
PROXY_PID=$!
sleep 2

echo "=========================================="
echo "CONFIG-BASED FILTERING TEST"
echo "=========================================="
echo ""

echo "--- Test 1: Normal API request (should be allowed) ---"
curl -s http://127.0.0.1:8080/api/users
echo -e "\n"

echo "--- Test 2: Admin path (should be blocked) ---"
curl -s http://127.0.0.1:8080/admin/users
echo -e "\n"

echo "--- Test 3: Protected path without auth (should be blocked) ---"
curl -s http://127.0.0.1:8080/protected/data
echo -e "\n"

echo "--- Test 4: Protected path WITH auth (should be allowed) ---"
curl -s -H "Authorization: Bearer token123" http://127.0.0.1:8080/protected/data
echo -e "\n"

echo "--- Test 5: Secret path (should be blocked) ---"
curl -s http://127.0.0.1:8080/secret/keys
echo -e "\n"

sleep 2

# Cleanup
kill $PROXY_PID 2>/dev/null
kill $BACKEND_PID 2>/dev/null
wait $PROXY_PID 2>/dev/null
wait $BACKEND_PID 2>/dev/null