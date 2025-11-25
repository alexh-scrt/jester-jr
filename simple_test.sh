#!/bin/bash
# Simple test script for jester-jr
set -e

echo "🚀 Starting Simple Jester Jr Test"

# Kill any existing processes
pkill -f "backend_server.py" 2>/dev/null || true
pkill -f "jester-jr" 2>/dev/null || true
sleep 2

echo "📦 Starting backend server..."
python3 ./backend_server.py &
BACKEND_PID=$!

echo "⏳ Waiting for backend to start..."
sleep 3

echo "🔧 Starting Jester Jr..."
./target/debug/jester-jr jester-jr.toml &
JESTER_PID=$!

echo "⏳ Waiting for Jester Jr to start..."
sleep 5

echo "🧪 Running tests..."

# Test 1: Basic health check
echo -n "Test 1 - Basic request: "
if curl -s http://127.0.0.1:8080/test | grep -q "Hello from backend"; then
    echo "✅ PASS"
else
    echo "❌ FAIL"
fi

# Test 2: API key test  
echo -n "Test 2 - API Key protection: "
if curl -s -H "jester-secret: FVDRuKEZw4LBnLxVkWjD" http://127.0.0.1:8080/test | grep -q "Hello from backend"; then
    echo "✅ PASS"
else
    echo "❌ FAIL"
fi

echo "🧹 Cleaning up..."
kill $JESTER_PID 2>/dev/null || true
kill $BACKEND_PID 2>/dev/null || true

echo "✅ Test completed!"