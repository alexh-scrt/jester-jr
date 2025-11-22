#!/bin/bash
# Generate self-signed certificates for testing Jester Jr TLS support
#
# This script creates:
# - Private key (RSA 2048-bit)
# - Self-signed certificate (valid for 365 days)
#
# For production, use Let's Encrypt or a proper CA instead!

set -e  # Exit on error

echo "🔐 Generating TLS certificates for Jester Jr..."
echo ""

# Create certs directory if it doesn't exist
mkdir -p certs
cd certs

# Check if certificates already exist
if [ -f "key.pem" ] && [ -f "cert.pem" ]; then
    echo "⚠️  Certificates already exist in ./certs/"
    read -p "   Overwrite them? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Certificate generation cancelled"
        exit 0
    fi
fi

echo "📝 Step 1: Generating private key..."
openssl genrsa -out key.pem 2048 2>/dev/null
chmod 600 key.pem
echo "   ✅ Private key generated: ./certs/key.pem"
echo ""

echo "📝 Step 2: Generating self-signed certificate..."
openssl req -new -x509 \
    -key key.pem \
    -out cert.pem \
    -days 365 \
    -subj "/C=US/ST=State/L=City/O=JesterJr/CN=localhost" \
    2>/dev/null
chmod 644 cert.pem
echo "   ✅ Certificate generated: ./certs/cert.pem"
echo ""

echo "📊 Certificate Information:"
openssl x509 -in cert.pem -noout -subject -dates
echo ""

echo "✅ Certificate generation complete!"
echo ""
echo "📁 Files created:"
echo "   • ./certs/key.pem  - Private key (keep secure!)"
echo "   • ./certs/cert.pem - Public certificate"
echo ""
echo "🔧 Update your jester-jr.toml:"
echo ""
cat << 'EOF'
[tls]
enabled = true
cert_file = "./certs/cert.pem"
key_file = "./certs/key.pem"
EOF
echo ""
echo "⚠️  Note: Self-signed certificates will show security warnings"
echo "   Use 'curl -k' to ignore certificate validation for testing"
echo ""
echo "🚀 Ready to test HTTPS!"