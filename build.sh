#!/bin/bash
set -e

echo "🐍 Attempting to use Python 3.11..."

# Try to find Python 3.11
if command -v python3.11 &> /dev/null; then
    echo "✅ Found Python 3.11"
    PYTHON_CMD="python3.11"
elif command -v python3.10 &> /dev/null; then
    echo "✅ Found Python 3.10, using as fallback"
    PYTHON_CMD="python3.10"
else
    echo "⚠️  Using default python3"
    PYTHON_CMD="python3"
fi

echo "🔧 Python version:"
$PYTHON_CMD --version

echo "📦 Installing dependencies with pre-compiled wheels..."
$PYTHON_CMD -m pip install --upgrade pip
$PYTHON_CMD -m pip install --only-binary=asyncpg,psycopg2-binary -r requirements.txt

echo "✅ Build complete!"
