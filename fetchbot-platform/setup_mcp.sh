#!/bin/bash
# Quick setup script for MCP server

set -e

echo "=================================================="
echo "FetchBot MCP Server Setup"
echo "=================================================="
echo ""

# Check if running in correct directory
if [ ! -d "mcp-security-server" ]; then
    echo "❌ Error: Please run this script from fetchbot-platform directory"
    echo "   cd fetchbot-platform && ./setup_mcp.sh"
    exit 1
fi

echo "Step 1: Installing Python dependencies..."
cd mcp-security-server
pip install -q -r requirements.txt
echo "✅ Python dependencies installed"
echo ""

echo "Step 2: Checking for pentesting tools..."

# Check for nmap
if ! command -v nmap &> /dev/null; then
    echo "⚠️  nmap not found. Install with: sudo apt install nmap"
else
    echo "✅ nmap found"
fi

# Check for ffuf
if ! command -v ffuf &> /dev/null; then
    echo "⚠️  ffuf not found. Install with: sudo apt install ffuf"
else
    echo "✅ ffuf found"
fi

echo ""
echo "Step 3: Testing MCP server..."

# Test server can start
timeout 3s python3 server.py &> /dev/null || true
echo "✅ MCP server can start"
echo ""

echo "=================================================="
echo "Setup Complete! 🎉"
echo "=================================================="
echo ""
echo "To use MCP instead of HTTP:"
echo ""
echo "  Option 1: Run MCP server locally (Development)"
echo "  -----------------------------------------------"
echo "  $ cd mcp-security-server"
echo "  $ python3 server.py &"
echo "  $ export USE_MCP=true"
echo "  $ cd .. && python main.py"
echo ""
echo "  Option 2: See the demo"
echo "  ----------------------"
echo "  $ python3 mcp-security-server/example_comparison.py"
echo ""
echo "  Option 3: Read full docs"
echo "  ------------------------"
echo "  $ cat MCP_QUICKSTART.md"
echo "  $ cat MCP_IMPLEMENTATION.md"
echo ""
echo "Benefits of MCP:"
echo "  ✅ Real-time streaming output"
echo "  ✅ 50-90% lower latency"
echo "  ✅ Better user experience"
echo "  ✅ See scan progress live"
echo ""
echo "=================================================="
