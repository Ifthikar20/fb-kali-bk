#!/usr/bin/env python3
"""
Example: HTTP vs MCP Comparison

Shows the difference in user experience between HTTP and MCP approaches.
"""

import asyncio
import time
import httpx


async def http_nmap_scan(target: str):
    """Traditional HTTP approach - wait for complete result"""
    print(f"\n🔴 HTTP Approach: Scanning {target}")
    print("→ User sees: 'Starting nmap scan...'")
    print("→ [Waiting... no updates for 3 minutes]")

    start = time.time()

    # Simulate HTTP request to Kali container
    async with httpx.AsyncClient(timeout=300.0) as client:
        # In reality, this would be:
        # response = await client.post("http://kali-agent-1:9000/execute_tool", ...)

        # Simulating 3 minute scan
        print("→ [User waits... scanning in progress but no visibility]")
        await asyncio.sleep(3)  # Simulated 3-minute wait

    elapsed = time.time() - start
    print(f"→ [After {elapsed:.1f}s] 'Nmap complete: Found 3 ports'")
    print("❌ User had NO idea what was happening for 3 minutes!\n")

    return {"open_ports": [22, 80, 443]}


async def mcp_nmap_scan(target: str):
    """MCP approach - streaming updates"""
    print(f"\n✅ MCP Approach: Scanning {target}")

    start = time.time()

    # Simulate MCP streaming updates
    updates = [
        (0.1, "→ User sees: 'Starting nmap scan...'"),
        (0.5, "→ User sees: 'Initializing scan engine'"),
        (0.8, "→ User sees: 'Scanning ports 1-1000'"),
        (1.0, "→ User sees: 'Found port 22/tcp open (SSH)'"),
        (1.5, "→ User sees: 'Scanning ports 1000-5000'"),
        (2.0, "→ User sees: 'Found port 80/tcp open (HTTP)'"),
        (2.5, "→ User sees: 'Scanning ports 5000-10000'"),
        (2.8, "→ User sees: 'Found port 443/tcp open (HTTPS)'"),
        (3.0, "→ User sees: 'Scan complete: 3 open ports found'")
    ]

    for delay, message in updates:
        await asyncio.sleep(delay - (time.time() - start))
        elapsed = time.time() - start
        print(f"[{elapsed:.1f}s] {message}")

    print("✅ User saw progress throughout the entire scan!\n")

    return {"open_ports": [22, 80, 443]}


async def http_directory_fuzzing(url: str):
    """HTTP: No progress on fuzzing"""
    print(f"\n🔴 HTTP Approach: Fuzzing {url}")
    print("→ User sees: 'Starting directory fuzzing...'")
    print("→ [Waiting 5+ minutes... complete silence]")

    await asyncio.sleep(3)  # Simulated wait

    print("→ [After 5 minutes] 'Fuzzing complete: Found 15 directories'")
    print("❌ User doesn't know if it's frozen or still running!\n")

    return {"directories_found": 15}


async def mcp_directory_fuzzing(url: str):
    """MCP: Streaming fuzzing results"""
    print(f"\n✅ MCP Approach: Fuzzing {url}")

    updates = [
        (0.1, "→ User sees: 'Starting directory fuzzing with 10,000 words'"),
        (0.3, "→ User sees: 'Tested 500 paths (5%)'"),
        (0.6, "→ User sees: 'Found: /admin (200 OK)'"),
        (0.9, "→ User sees: 'Tested 1500 paths (15%)'"),
        (1.2, "→ User sees: 'Found: /api (200 OK)'"),
        (1.5, "→ User sees: 'Tested 3000 paths (30%)'"),
        (1.8, "→ User sees: 'Found: /uploads (403 Forbidden)'"),
        (2.1, "→ User sees: 'Tested 5000 paths (50%)'"),
        (2.4, "→ User sees: 'Found: /backup (200 OK)'"),
        (2.7, "→ User sees: 'Tested 7500 paths (75%)'"),
        (3.0, "→ User sees: 'Fuzzing complete: 15 directories found'")
    ]

    start = time.time()
    for delay, message in updates:
        await asyncio.sleep(delay - (time.time() - start))
        elapsed = time.time() - start
        print(f"[{elapsed:.1f}s] {message}")

    print("✅ User saw progress and results as they were discovered!\n")

    return {"directories_found": 15}


async def demonstrate_advantages():
    """Show all advantages of MCP"""

    print("=" * 70)
    print("FETCHBOT: HTTP vs MCP Comparison")
    print("=" * 70)

    # Example 1: Nmap scan
    print("\n📍 Example 1: Nmap Port Scan")
    print("-" * 70)
    await http_nmap_scan("example.com")
    await mcp_nmap_scan("example.com")

    # Example 2: Directory fuzzing
    print("\n📍 Example 2: Directory Fuzzing")
    print("-" * 70)
    await http_directory_fuzzing("https://example.com")
    await mcp_directory_fuzzing("https://example.com")

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY: Why MCP is Better for FetchBot")
    print("=" * 70)

    print("""
✅ MCP ADVANTAGES:

1. **User Experience**
   - Real-time progress updates
   - Know when tools are working vs frozen
   - See results as they're discovered
   - Can make decisions earlier

2. **Performance**
   - Lower latency (no HTTP overhead)
   - Persistent connection (no reconnecting)
   - Streaming reduces memory usage

3. **Visibility**
   - See tool stdout/stderr in real-time
   - Progress bars and percentages
   - Partial results before completion

4. **Control**
   - Can cancel long-running scans
   - Pause/resume capability
   - Better error handling

5. **Developer Experience**
   - Easier debugging (see output immediately)
   - Standard protocol (well-documented)
   - Better error messages

❌ HTTP DISADVANTAGES:

1. User sees nothing during execution
2. Looks frozen for long scans
3. Can't tell if tool is working or stuck
4. Higher latency
5. Request/response overhead
6. No partial results
7. Harder to cancel

RECOMMENDATION: Use MCP for FetchBot! 🎯
    """)

    print("=" * 70)
    print("\nTo implement MCP:")
    print("  1. cd fetchbot-platform/mcp-security-server")
    print("  2. pip install -r requirements.txt")
    print("  3. python3 server.py")
    print("  4. export USE_MCP=true")
    print("  5. Run your scans - now with streaming!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(demonstrate_advantages())
