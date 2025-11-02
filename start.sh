#!/bin/bash
echo "🧹 Cleaning up previous processes..."

# Kill all Node.js processes
pkill -f node
sleep 2

# Kill any process on port 3000
fuser -k 3000/tcp 2>/dev/null || true
sleep 2

# Remove any node modules issues
if [ -d "node_modules" ]; then
    echo "🔄 Reinstalling dependencies..."
    rm -rf node_modules
    npm install
fi

echo "🚀 Starting Tesam Blockchain Explorer..."
node server.js