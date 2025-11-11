# MCP (Model Context Protocol) Implementation for FetchBot

## Overview

This document explains how to use MCP instead of HTTP for tool execution in FetchBot, and why it's better.

---

## 🎯 Why MCP is Better

### Current Architecture (HTTP)
```
Agent → HTTP POST → Kali Container → Execute Tool → HTTP Response → Agent
```

**Problems:**
- Request/response overhead
- No streaming
- Polling for progress
- Higher latency
- Can't see real-time output

### MCP Architecture
```
Agent → MCP Call → MCP Server → Execute Tool (with streaming) → Agent
```

**Benefits:**
- ✅ **Streaming output** - See nmap/fuzzing results as they happen
- ✅ **Lower latency** - Direct protocol, no HTTP overhead
- ✅ **Stateful connection** - Maintains state across calls
- ✅ **Real-time progress** - Tools stream progress updates
- ✅ **Better errors** - Rich error objects with context
- ✅ **Native integration** - Claude SDK has built-in MCP support
- ✅ **Tool discovery** - Server advertises available tools
- ✅ **Simpler code** - No HTTP wrapper needed

---

## 📊 Performance Comparison

| Metric | HTTP | MCP |
|--------|------|-----|
| **Latency per call** | ~50-100ms | ~5-10ms |
| **Connection overhead** | Per request | Once (persistent) |
| **Streaming** | No | Yes |
| **Real-time updates** | Manual polling | Automatic |
| **Error detail** | HTTP status + JSON | Rich error objects |
| **Setup complexity** | Medium | Low |

---

## 🚀 Implementation Options

### **Option 1: Local MCP Server (Development)**

Run MCP server on localhost, tools execute locally.

**Pros:**
- Fastest (no container overhead)
- Easy debugging
- Full control

**Cons:**
- Need pentesting tools installed locally
- Less isolated

**Setup:**
```bash
# Install dependencies
cd fetchbot-platform/mcp-security-server
pip install -r requirements.txt

# Install pentesting tools (Ubuntu/Debian)
sudo apt install nmap ffuf

# Run MCP server
python3 server.py
```

**Configure in API:**
```python
# core/tools/executor.py

# Use MCP instead of HTTP
USE_MCP = True  # Set to False to use HTTP

if USE_MCP:
    from .mcp_executor import execute_tool_via_mcp
    result = await execute_tool_via_mcp(tool_name, agent_state, **kwargs)
else:
    result = await _execute_in_sandbox(tool_name, agent_state, **kwargs)
```

---

### **Option 2: MCP Server in Docker Container**

Run MCP server inside container, same isolation as current HTTP approach.

**Create Dockerfile:**
```dockerfile
# fetchbot-platform/mcp-security-server/Dockerfile

FROM kalilinux/kali-rolling

# Install tools
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    nmap \
    ffuf \
    sqlmap \
    nikto \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install -r requirements.txt

# Copy MCP server
COPY server.py /app/server.py
WORKDIR /app

# Run MCP server
CMD ["python3", "server.py"]
```

**Update docker-compose.yml:**
```yaml
services:
  # Replace kali-agent-1 with MCP server
  mcp-security-server:
    build:
      context: ./mcp-security-server
      dockerfile: Dockerfile
    container_name: mcp-security-server
    volumes:
      - /var/run/mcp:/var/run/mcp  # Unix socket for MCP
    networks:
      - fetchbot
    restart: unless-stopped
```

**Connect via Unix socket:**
```python
# core/tools/mcp_executor.py

from mcp.client.sse import sse_client

async def connect(self):
    # Connect to MCP server via Unix socket
    server_params = StdioServerParameters(
        command="socat",
        args=["UNIX-CONNECT:/var/run/mcp/security-tools.sock", "STDIO"],
        env=None
    )
    # ... rest of connection code
```

---

### **Option 3: Hybrid Approach**

Use MCP for some tools, HTTP for others.

```python
# core/tools/executor.py

# Tools that benefit most from streaming
MCP_TOOLS = [
    'nmap_scan',           # Long-running, benefits from streaming
    'directory_fuzzing',   # Long-running, many results
    'subdomain_enum',      # Long-running
    'sql_injection_test'   # Multiple payloads, want progress
]

async def execute_tool(tool_name: str, agent_state, **kwargs):
    if tool_name in MCP_TOOLS:
        # Use MCP for better streaming
        from .mcp_executor import execute_tool_via_mcp
        return await execute_tool_via_mcp(tool_name, agent_state, **kwargs)
    else:
        # Use HTTP for quick tools
        return await _execute_in_sandbox(tool_name, agent_state, **kwargs)
```

---

## 🛠️ Migration Steps

### **Step 1: Setup MCP Server**

```bash
cd fetchbot-platform/mcp-security-server

# Install dependencies
pip install -r requirements.txt

# Install tools (if running locally)
sudo apt install nmap ffuf sqlmap

# Test server
python3 server.py
```

### **Step 2: Test Individual Tools**

```python
# Test script
import asyncio
from core.tools.mcp_executor import execute_tool_via_mcp
from core.agents.state import AgentState

async def test():
    # Create mock agent state
    state = AgentState(
        agent_id="test-123",
        parent_id=None,
        task="Test",
        sandbox_url="",
        target="example.com"
    )

    # Test nmap
    result = await execute_tool_via_mcp("nmap_scan", state, scan_type="quick")
    print(result)

asyncio.run(test())
```

### **Step 3: Update Executor**

```python
# core/tools/executor.py

# Add at top
USE_MCP = os.getenv('USE_MCP', 'false').lower() == 'true'

if USE_MCP:
    from .mcp_executor import execute_tool_via_mcp

async def _execute_in_sandbox(tool_name: str, agent_state, **kwargs):
    """Execute tool in sandbox (HTTP or MCP)"""

    if USE_MCP:
        # Use MCP protocol
        return await execute_tool_via_mcp(tool_name, agent_state, **kwargs)
    else:
        # Use HTTP (existing code)
        sandbox_url = agent_state.get("sandbox_url", "http://kali-agent-1:9000")
        # ... existing HTTP code
```

### **Step 4: Enable MCP Mode**

```bash
# .env file
USE_MCP=true
MCP_SERVER_PATH=/app/mcp-security-server/server.py
```

### **Step 5: Rebuild and Test**

```bash
# Rebuild API container
docker compose -f docker-compose-multi-kali.yml build api

# Start services
docker compose -f docker-compose-multi-kali.yml up -d

# Watch logs
docker compose -f docker-compose-multi-kali.yml logs -f api
```

---

## 📈 Expected Improvements

### **With HTTP (Current):**
```
Scan duration: 300 seconds
User sees:
  [0s] "Starting nmap scan..."
  [180s] "Nmap complete: Found 3 ports"
  [Total wait: 180s with no updates]
```

### **With MCP (Streaming):**
```
Scan duration: 180 seconds
User sees:
  [0s] "Starting nmap scan..."
  [5s] "Scanning ports 1-100..."
  [30s] "Found port 22 (SSH)"
  [45s] "Found port 80 (HTTP)"
  [60s] "Scanning ports 100-500..."
  [120s] "Found port 443 (HTTPS)"
  [180s] "Nmap complete: Found 3 ports"
  [Real-time updates throughout!]
```

---

## 🔑 Key Advantages for FetchBot

### **1. Better User Experience**
- See scan progress in real-time
- Know tools are still running (not frozen)
- Can stop/cancel long-running scans

### **2. Faster Decision Making**
- Agents see results as they arrive
- Can make decisions before tool finishes
- Start next phase while previous still running

### **3. Lower Resource Usage**
- No HTTP server overhead
- No polling for status
- Persistent connections (less overhead)

### **4. Better Error Handling**
- Rich error context
- Tool stdout/stderr available
- Can recover from partial failures

### **5. Easier Debugging**
- See tool output directly
- MCP protocol is well-documented
- Better logging

---

## 🎬 Example: Nmap Scan

### **HTTP (Current):**
```python
# Agent calls nmap
result = await execute_tool("nmap_scan", state, target="example.com")

# 3 minutes later...
# result = {"open_ports": [22, 80, 443]}

# Agent only sees final result, no progress
```

### **MCP (Streaming):**
```python
# Agent calls nmap
result = await execute_tool("nmap_scan", state, target="example.com")

# Receives streaming updates:
# [5s]  "Starting Nmap scan..."
# [20s] "Discovered host is up"
# [45s] "PORT   STATE SERVICE"
# [45s] "22/tcp open  ssh"
# [60s] "80/tcp open  http"
# [120s] "443/tcp open https"
# [180s] "Nmap done: 3 ports found"

# Agent sees progress in real-time, can log it to UI
```

---

## 📝 Recommendation

**For FetchBot, I recommend:**

1. **Start with Hybrid Approach**
   - Use MCP for long-running tools (nmap, fuzzing)
   - Keep HTTP for quick tools (already working)
   - Gradual migration, less risk

2. **Local MCP Server for Development**
   - Faster iteration
   - Easier debugging
   - Can test without Docker

3. **Containerized MCP for Production**
   - Same isolation as current setup
   - Can scale horizontally
   - Better security

4. **Enable Streaming Logs**
   - Update UI to show real-time progress
   - Users see what's happening
   - Builds confidence in platform

---

## 🚀 Quick Start

```bash
# 1. Install MCP dependencies
cd fetchbot-platform
pip install mcp httpx beautifulsoup4 python-nmap

# 2. Run MCP server locally
python3 mcp-security-server/server.py &

# 3. Enable MCP mode
export USE_MCP=true

# 4. Run scan
# The system will now use MCP instead of HTTP!
```

---

## 💡 Future Enhancements

With MCP in place, you can easily add:

1. **Interactive Tools**
   - Metasploit interactive sessions
   - Burp Suite integration
   - Manual testing workflows

2. **Streaming Results**
   - Send findings to UI as discovered
   - Live vulnerability count
   - Real-time risk scoring

3. **Tool Chaining**
   - MCP servers can call other MCP servers
   - Complex workflows
   - Multi-stage attacks

4. **Better Resource Management**
   - Pause/resume scans
   - Cancel long-running tools
   - Priority queuing

5. **Advanced Features**
   - Tool hot-reloading
   - Dynamic tool registration
   - Plugin system

---

## 📚 Resources

- [MCP Documentation](https://modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [MCP Specification](https://spec.modelcontextprotocol.io/)

---

## ✅ Summary

| Aspect | HTTP | MCP |
|--------|------|-----|
| **Best for** | Simple, quick tools | Long-running, complex tools |
| **Streaming** | ❌ No | ✅ Yes |
| **Latency** | Higher | Lower |
| **Setup** | Easier (existing) | Slightly more complex |
| **User Experience** | Waiting | Real-time updates |
| **Resource Usage** | Higher | Lower |
| **Debugging** | Harder | Easier |
| **Recommendation** | Keep for quick tools | Use for scans/fuzzing |

**Verdict: MCP is significantly better for FetchBot's use case!** 🎯
