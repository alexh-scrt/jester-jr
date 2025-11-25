#!/bin/bash
echo "🧹 Clearing test blacklist..."
echo '{"entries":[]}' > test-blacklist.json
echo "✅ Blacklist cleared!"
echo "💡 You can now restart jester-jr and run tests again."