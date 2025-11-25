#!/bin/bash
# Reset blacklist and run curl tests
echo "🧹 Clearing blacklist before tests..."

# Clear the blacklist file
cat > clean-blacklist.json << 'EOF'
{
  "entries": []
}
EOF

echo "📋 Blacklist cleared. Starting tests..."
echo ""

# Run the curl tests
./curl_tests.sh