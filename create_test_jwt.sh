#!/bin/bash
# Create a test JWT token for jester-jr testing
# This creates a JWT with the payload: {"sub": "testuser", "iss": "jester-jr-test", "aud": "api", "exp": 9999999999}

# JWT Header: {"alg": "HS256", "typ": "JWT"}
HEADER=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=\n' | tr '/+' '_-')

# JWT Payload: {"sub": "testuser", "iss": "jester-jr-test", "aud": "api", "exp": 9999999999}
PAYLOAD=$(echo -n '{"sub":"testuser","iss":"jester-jr-test","aud":"api","exp":9999999999}' | base64 | tr -d '=\n' | tr '/+' '_-')

# For a real JWT, we'd need to create an HMAC-SHA256 signature with the secret
# For testing purposes, let's create a dummy signature (this won't validate in production)
SIGNATURE="dummy-signature-for-testing"

JWT="$HEADER.$PAYLOAD.$SIGNATURE"

echo "Test JWT (unsigned, for testing only): $JWT"
echo ""
echo "Header: $HEADER"
echo "Payload: $PAYLOAD"
echo ""
echo "Note: This is a dummy JWT for basic testing. Real validation will require proper HMAC signature."