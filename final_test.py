#!/usr/bin/env python3
"""
Final test script for jester-jr v0.1.0 release
Tests all core functionality to validate release readiness
"""
import subprocess
import time
import requests
import json
import os
import signal

def start_process(cmd):
    """Start a process and return the Popen object"""
    return subprocess.Popen(cmd, shell=True)

def cleanup_processes():
    """Kill any existing jester-jr or backend processes"""
    os.system("pkill -f 'backend_server.py' 2>/dev/null || true")
    os.system("pkill -f 'jester-jr' 2>/dev/null || true")
    time.sleep(2)

def test_jester_jr():
    """Run comprehensive jester-jr tests"""
    print("🚀 Jester Jr v0.1.0 Release Test Suite")
    print("=" * 50)
    
    cleanup_processes()
    
    # Clear blacklist
    with open("clean-blacklist.json", "w") as f:
        json.dump({"entries": []}, f)
    
    print("📦 Starting backend server...")
    backend = start_process("python3 ./backend_server.py")
    time.sleep(3)
    
    print("🔧 Starting Jester Jr...")
    proxy = start_process("./target/debug/jester-jr working-test.toml")
    time.sleep(5)
    
    tests_passed = 0
    tests_total = 0
    
    # Test 1: Health check (no auth required)
    tests_total += 1
    try:
        response = requests.get("http://127.0.0.1:8090/health", timeout=5)
        if response.status_code == 200 and "Hello" in response.text:
            print("✅ Test 1: Health check - PASS")
            tests_passed += 1
        else:
            print(f"❌ Test 1: Health check - FAIL (status: {response.status_code})")
    except Exception as e:
        print(f"❌ Test 1: Health check - FAIL (error: {e})")
    
    # Test 2: Basic request (should work via catch-all route)
    tests_total += 1
    try:
        response = requests.get("http://127.0.0.1:8090/test", timeout=5)
        if response.status_code == 200 and "Hello" in response.text:
            print("✅ Test 2: Basic request - PASS")
            tests_passed += 1
        else:
            print(f"❌ Test 2: Basic request - FAIL (status: {response.status_code})")
    except Exception as e:
        print(f"❌ Test 2: Basic request - FAIL (error: {e})")
    
    # Test 3: API Key authentication
    tests_total += 1
    try:
        headers = {"x-api-key": "test-key-123"}
        response = requests.get("http://127.0.0.1:8090/api/public/users", headers=headers, timeout=5)
        if response.status_code == 200:
            print("✅ Test 3: API Key auth - PASS")
            tests_passed += 1
        else:
            print(f"❌ Test 3: API Key auth - FAIL (status: {response.status_code})")
    except Exception as e:
        print(f"❌ Test 3: API Key auth - FAIL (error: {e})")
    
    # Test 4: Jester-Secret authentication
    tests_total += 1
    try:
        headers = {"jester-secret": "FVDRuKEZw4LBnLxVkWjD"}
        response = requests.get("http://127.0.0.1:8090/api/secure/data", headers=headers, timeout=5)
        if response.status_code == 200:
            print("✅ Test 4: Jester-Secret auth - PASS")
            tests_passed += 1
        else:
            print(f"❌ Test 4: Jester-Secret auth - FAIL (status: {response.status_code})")
    except Exception as e:
        print(f"❌ Test 4: Jester-Secret auth - FAIL (error: {e})")
    
    # Test 5: Unauthorized request (should be blocked)
    tests_total += 1
    try:
        response = requests.get("http://127.0.0.1:8090/api/secure/data", timeout=5)
        if response.status_code in [401, 403]:
            print("✅ Test 5: Unauthorized blocking - PASS")
            tests_passed += 1
        else:
            print(f"❌ Test 5: Unauthorized blocking - FAIL (status: {response.status_code}, should be 401/403)")
    except requests.exceptions.RequestException:
        print("✅ Test 5: Unauthorized blocking - PASS (connection rejected)")
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 5: Unauthorized blocking - FAIL (error: {e})")
    
    # Test 6: Invalid API key (should be blocked)
    tests_total += 1
    try:
        headers = {"x-api-key": "invalid-key"}
        response = requests.get("http://127.0.0.1:8090/api/public/users", headers=headers, timeout=5)
        if response.status_code in [401, 403]:
            print("✅ Test 6: Invalid API key blocking - PASS")
            tests_passed += 1
        else:
            print(f"❌ Test 6: Invalid API key blocking - FAIL (status: {response.status_code})")
    except requests.exceptions.RequestException:
        print("✅ Test 6: Invalid API key blocking - PASS (connection rejected)")
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 6: Invalid API key blocking - FAIL (error: {e})")
    
    # Cleanup
    print("\n🧹 Cleaning up...")
    proxy.terminate()
    backend.terminate()
    
    try:
        proxy.wait(timeout=5)
        backend.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proxy.kill()
        backend.kill()
    
    # Results
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {tests_passed}/{tests_total} tests passed")
    print(f"🎯 Success Rate: {(tests_passed/tests_total)*100:.1f}%")
    
    if tests_passed == tests_total:
        print("🎉 ALL TESTS PASSED! Jester Jr v0.1.0 is ready for release!")
        return True
    else:
        print(f"❌ {tests_total - tests_passed} test(s) failed. Please review before release.")
        return False

if __name__ == "__main__":
    success = test_jester_jr()
    exit(0 if success else 1)