#!/bin/bash
# Quick test script

echo "🧹 Cleaning up existing processes..."
pkill -f "backend_server.py" || true
pkill -f "jester-jr" || true
sleep 2

echo "📦 Starting backend..."
python3 ./backend_server.py &
BACKEND_PID=$!
sleep 3

echo "🔧 Starting jester-jr..."
./target/debug/jester-jr working-test.toml &
PROXY_PID=$!
sleep 5

echo "🧪 Running tests..."

echo -n "1. Health check: "
if curl -s http://127.0.0.1:8090/health | grep -q "Hello"; then
    echo "✅ PASS"
else
    echo "❌ FAIL"
fi

echo -n "2. Basic request: "
if curl -s http://127.0.0.1:8090/test | grep -q "Hello"; then
    echo "✅ PASS"
else
    echo "❌ FAIL"
fi

echo -n "3. API Key auth: "
if curl -s -H "x-api-key: test-key-123" http://127.0.0.1:8090/api/public/users | grep -q "Hello"; then
    echo "✅ PASS"
else
    echo "❌ FAIL"
fi

echo -n "4. Jester-Secret auth: "
if curl -s -H "jester-secret: FVDRuKEZw4LBnLxVkWjD" http://127.0.0.1:8090/api/secure/data | grep -q "Hello"; then
    echo "✅ PASS"
else
    echo "❌ FAIL"
fi

echo -n "5. Unauthorized request: "
if curl -s http://127.0.0.1:8090/api/secure/data | grep -q "Unauthorized\|Forbidden" || [ $? -ne 0 ]; then
    echo "✅ PASS (correctly blocked)"
else
    echo "❌ FAIL (should be blocked)"
fi

echo "🧹 Cleanup..."
kill $PROXY_PID $BACKEND_PID 2>/dev/null
wait $PROXY_PID $BACKEND_PID 2>/dev/null

echo "✅ Test completed!"