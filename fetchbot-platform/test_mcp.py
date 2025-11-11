#!/usr/bin/env python3
"""
Test MCP integration standalone
"""

import asyncio
from core.tools.mcp_executor import execute_tool_via_mcp

class MockAgentState:
    """Mock agent state for testing"""
    def __init__(self, target):
        self.target = target
        self.agent_id = "test-agent"
        self.job_id = "test-job"

async def test_mcp_tools():
    """Test MCP tools"""

    print("=" * 70)
    print("Testing MCP Security Tools")
    print("=" * 70)

    # Create mock state
    state = MockAgentState(target="scanme.nmap.org")

    print(f"\n📍 Target: {state.target}\n")

    # Test 1: Nmap scan
    print("🔍 Test 1: Nmap Quick Scan")
    print("-" * 70)
    try:
        result = await execute_tool_via_mcp(
            "nmap_scan",
            state,
            scan_type="quick"
        )
        print(f"✅ Success: {result['success']}")
        print(f"📊 Result:\n{result.get('result', 'No output')[:500]}")
    except Exception as e:
        print(f"❌ Error: {e}")

    print("\n")

    # Test 2: HTTP scan
    print("🌐 Test 2: HTTP Scan")
    print("-" * 70)
    state2 = MockAgentState(target="http://scanme.nmap.org")
    try:
        result = await execute_tool_via_mcp(
            "http_scan",
            state2
        )
        print(f"✅ Success: {result['success']}")
        print(f"📊 Result:\n{result.get('result', 'No output')[:500]}")
    except Exception as e:
        print(f"❌ Error: {e}")

    print("\n" + "=" * 70)
    print("✅ MCP Testing Complete!")
    print("=" * 70)

if __name__ == "__main__":
    asyncio.run(test_mcp_tools())
