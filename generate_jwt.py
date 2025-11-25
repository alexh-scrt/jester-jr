#!/usr/bin/env python3
"""
Generate a test JWT token for jester-jr testing
"""
import jwt
import json
from datetime import datetime, timedelta

# JWT configuration matching test-jester-jr.toml
SECRET = "test-secret-for-jwt-validation"
PAYLOAD = {
    "sub": "testuser",
    "iss": "jester-jr-test", 
    "aud": "api",
    "exp": int((datetime.now() + timedelta(days=365)).timestamp()),  # Valid for 1 year
    "iat": int(datetime.now().timestamp())
}

# Generate JWT token
token = jwt.encode(PAYLOAD, SECRET, algorithm="HS256")

print(f"JWT Token: {token}")
print(f"Payload: {json.dumps(PAYLOAD, indent=2)}")

# Verify the token works
try:
    decoded = jwt.decode(token, SECRET, algorithms=["HS256"], audience="api", issuer="jester-jr-test")
    print("✅ Token verification successful")
    print(f"Decoded: {json.dumps(decoded, indent=2)}")
except Exception as e:
    print(f"❌ Token verification failed: {e}")