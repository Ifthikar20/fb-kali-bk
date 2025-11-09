# FetchBot.ai - Complete Setup & Testing Guide

## ✅ All Issues Fixed!

We've resolved all dependency and configuration issues. Follow this guide to run the system successfully.

---

## 🔧 What Was Fixed

1. ✅ **Added `use_dynamic_agents` to Settings class** (config.py)
2. ✅ **Added jinja2 dependency** (requirements.txt)
3. ✅ **Added email-validator dependency** (requirements.txt)

---

## 📋 Prerequisites

- Docker & Docker Compose installed
- Anthropic API key (get from https://console.anthropic.com/)

---

## 🚀 Complete Setup Steps

### Step 1: Create .env File

```bash
cd fetchbot-platform

# Create .env file
cat > .env << 'EOF'
# Database
DATABASE_URL=postgresql://fetchbot:fetchbot123@postgres:5432/fetchbot

# Redis
REDIS_URL=redis://redis:6379/0

# AI - REPLACE WITH YOUR ACTUAL KEY!
ANTHROPIC_API_KEY=sk-ant-api03-your-actual-key-here

# Security
SECRET_KEY=change-this-to-random-string-in-production

# ⭐ ENABLE DYNAMIC AGENTS! ⭐
USE_DYNAMIC_AGENTS=true
EOF

# Edit to add your actual API key
nano .env
```

**IMPORTANT:** Replace `sk-ant-api03-your-actual-key-here` with your real Anthropic API key!

---

### Step 2: Clean Up Old Containers

```bash
# Stop all containers
docker-compose down

# Remove orphan containers
docker stop kali-agent-1 kali-agent-2 kali-agent-3 2>/dev/null || true
docker rm kali-agent-1 kali-agent-2 kali-agent-3 2>/dev/null || true

# Optional: Clean up Docker system
docker system prune -f
```

---

### Step 3: Build API Container

```bash
# Build API with latest fixes
docker-compose build api --no-cache

# This will take ~30-60 seconds
# It's installing all dependencies including:
# - jinja2 (for prompts)
# - email-validator (for Pydantic)
# - anthropic (for Claude)
```

---

### Step 4: Start All Services

```bash
# Start in background
docker-compose up -d

# Or watch logs in real-time
docker-compose up
```

**Expected Output:**
```
[+] Running 6/6
 ✔ Container fetchbot-postgres     Healthy
 ✔ Container fetchbot-redis        Healthy
 ✔ Container fetchbot-api          Started
 ✔ Container fetchbot-network-bot  Started
 ✔ Container fetchbot-ui-bot       Started
 ✔ Container fetchbot-db-bot       Started
```

---

### Step 5: Verify API is Running

```bash
# Check container status (should show "Up")
docker-compose ps

# Should show:
# NAME              STATUS
# fetchbot-api     Up               # ✅ NOT "Restarting"!
```

---

### Step 6: Check Logs for Success Message

```bash
# View API logs
docker-compose logs api | head -30

# ✅ YOU SHOULD SEE THIS:
# [INIT] ✨ Using DYNAMIC MULTI-AGENT orchestrator (AI-driven agent creation)
# INFO - Registered tool: create_agent (sandbox=False)
# INFO - Registered tool: api_fuzzing (sandbox=True)
# INFO - Registered tool: sql_injection_test (sandbox=True)
# ... (30+ tools)
# INFO:     Application startup complete.
# INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

### Step 7: Test API Health

```bash
# Test health endpoint
curl http://localhost:8000/health

# ✅ Expected response:
# {"status":"healthy"}

# Test API docs
open http://localhost:8000/docs
```

---

### Step 8: Verify Tools are Registered

```bash
# Check tool registry
docker-compose exec api python -c "
from core.tools.registry import list_tools
tools = list_tools()
print(f'✅ Tools registered: {len(tools)}')
for tool in sorted(tools)[:10]:
    print(f'  - {tool}')
"

# ✅ Expected output:
# ✅ Tools registered: 34
#   - agent_finish
#   - api_brute_force
#   - api_fuzzing
#   - api_idor_test
#   - create_agent
#   - create_vulnerability_report
#   - ...
```

---

## 🧪 Run Your First Scan!

### Step 1: Register a User

```bash
# Register user via API
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpass123",
    "organization_name": "Test Organization"
  }' | jq

# Save the access_token from the response
```

**Or use API Docs (easier):**
1. Go to http://localhost:8000/docs
2. Find `POST /auth/register`
3. Click "Try it out"
4. Enter the JSON above
5. Copy the `access_token`

---

### Step 2: Start a Security Scan

**Using cURL:**

```bash
# Set your token
TOKEN="paste_your_token_here"

# Start scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "http://testphp.vulnweb.com",
    "organization_id": 1
  }' | jq

# Save the job_id from response
```

**Or use API Docs:**
1. Find `POST /scan`
2. Click the lock icon 🔒
3. Paste your token, click "Authorize"
4. Click "Try it out"
5. Enter:
```json
{
  "target": "http://testphp.vulnweb.com",
  "organization_id": 1
}
```
6. Click "Execute"
7. Copy the `job_id`

---

### Step 3: Watch the Magic! 🪄

**Monitor Logs:**

```bash
# In a new terminal, watch what's happening
docker-compose logs -f api

# You'll see Claude making decisions:
# INFO - Root coordinator initialized for target: http://testphp.vulnweb.com
# INFO - Initialized agent: Reconnaissance Agent
# INFO - Tool 'http_scan' executed successfully
# INFO - Created agent: API Security Agent with modules ['api_testing']
# INFO - Tool 'api_fuzzing' executed successfully
```

**Check Scan Status:**

```bash
# Replace with your job_id
JOB_ID="your_job_id_here"

# Check status
curl http://localhost:8000/scan/$JOB_ID \
  -H "Authorization: Bearer $TOKEN" | jq

# View agent graph
curl http://localhost:8000/scan/$JOB_ID/agent-graph \
  -H "Authorization: Bearer $TOKEN" | jq '.graph.nodes[] | {name, status, findings: .findings_count}'
```

---

## 🎯 Complete Testing Script

Save this as `test-system.sh`:

```bash
#!/bin/bash
set -e

echo "🧪 FetchBot Dynamic Agent System - Complete Test"
echo "================================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test 1: Health Check
echo -e "\n${BLUE}Test 1: API Health Check${NC}"
if curl -s http://localhost:8000/health | grep -q "healthy"; then
    echo -e "${GREEN}✅ API is healthy${NC}"
else
    echo -e "${RED}❌ API not responding${NC}"
    exit 1
fi

# Test 2: Check dynamic agents
echo -e "\n${BLUE}Test 2: Dynamic Agent System${NC}"
if docker-compose logs api | grep -q "DYNAMIC MULTI-AGENT"; then
    echo -e "${GREEN}✅ Dynamic agents enabled${NC}"
else
    echo -e "${RED}❌ Dynamic agents NOT enabled${NC}"
    exit 1
fi

# Test 3: Tool registry
echo -e "\n${BLUE}Test 3: Tool Registry${NC}"
TOOL_COUNT=$(docker-compose exec -T api python -c "from core.tools.registry import list_tools; print(len(list_tools()))" 2>/dev/null)
if [ "$TOOL_COUNT" -gt 30 ]; then
    echo -e "${GREEN}✅ $TOOL_COUNT tools registered${NC}"
else
    echo -e "${RED}❌ Tools not registered${NC}"
    exit 1
fi

# Test 4: Register user
echo -e "\n${BLUE}Test 4: User Registration${NC}"
RESPONSE=$(curl -s -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"test$(date +%s)@example.com\",\"password\":\"test123\",\"organization_name\":\"Test\"}")

TOKEN=$(echo $RESPONSE | jq -r '.access_token')
if [ "$TOKEN" != "null" ] && [ -n "$TOKEN" ]; then
    echo -e "${GREEN}✅ User registered${NC}"
else
    echo -e "${RED}❌ Registration failed${NC}"
    exit 1
fi

# Test 5: Start scan
echo -e "\n${BLUE}Test 5: Start Security Scan${NC}"
SCAN=$(curl -s -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target":"http://testphp.vulnweb.com","organization_id":1}')

JOB_ID=$(echo $SCAN | jq -r '.job_id')
if [ "$JOB_ID" != "null" ]; then
    echo -e "${GREEN}✅ Scan started: $JOB_ID${NC}"
else
    echo -e "${RED}❌ Scan failed${NC}"
    exit 1
fi

echo -e "\n${GREEN}🎉 All tests passed!${NC}"
echo "================================================="
echo ""
echo "Monitor your scan:"
echo "  curl http://localhost:8000/scan/$JOB_ID -H 'Authorization: Bearer $TOKEN' | jq"
echo ""
echo "View agent graph:"
echo "  curl http://localhost:8000/scan/$JOB_ID/agent-graph -H 'Authorization: Bearer $TOKEN' | jq"
echo ""
echo "Watch logs:"
echo "  docker-compose logs -f api"
```

**Run it:**

```bash
chmod +x test-system.sh
./test-system.sh
```

---

## ❌ Troubleshooting

### Issue: API keeps restarting

**Check logs:**
```bash
docker-compose logs api --tail=50
```

**Common causes:**
1. Missing ANTHROPIC_API_KEY → Add to .env
2. Invalid API key → Check key at console.anthropic.com
3. Database not ready → Wait 30 seconds and restart

**Fix:**
```bash
docker-compose down
docker-compose up -d
```

---

### Issue: "Connection refused" on curl

**Check if API is running:**
```bash
docker-compose ps | grep api

# Should show "Up", not "Restarting"
```

**If restarting, check logs:**
```bash
docker-compose logs api
```

---

### Issue: No tools registered

**Rebuild container:**
```bash
docker-compose down
docker-compose build api --no-cache
docker-compose up -d
```

---

## 📊 What Success Looks Like

### Container Status
```bash
docker-compose ps

NAME                STATUS
fetchbot-api       Up         ✅
fetchbot-postgres  Up (healthy) ✅
fetchbot-redis     Up (healthy) ✅
```

### Logs
```
[INIT] ✨ Using DYNAMIC MULTI-AGENT orchestrator (AI-driven agent creation)
INFO - Registered tool: create_agent (sandbox=False)
INFO - Registered tool: api_fuzzing (sandbox=True)
... (30+ tools)
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Health Check
```bash
curl http://localhost:8000/health
# {"status":"healthy"}
```

---

## 🎉 You're Ready!

The dynamic agent system is now running successfully. When you start a scan:

1. **Root Coordinator** analyzes the target
2. **Recon Agent** discovers attack surface
3. **Specialized Agents** created dynamically:
   - API Security Agent (if APIs found)
   - SQL Injection Agent (if database detected)
   - XSS Agent (if forms found)
4. **Findings aggregated** and returned

All decisions made by Claude AI - no hardcoding! 🚀

---

## 📝 Quick Reference

```bash
# Start system
docker-compose up -d

# Stop system
docker-compose down

# View logs
docker-compose logs -f api

# Rebuild
docker-compose build api --no-cache

# Health check
curl http://localhost:8000/health

# API docs
open http://localhost:8000/docs
```

---

## 🆘 Need Help?

If something doesn't work:

1. Check logs: `docker-compose logs api --tail=100`
2. Verify .env: `cat .env | grep USE_DYNAMIC_AGENTS`
3. Rebuild: `docker-compose build api --no-cache`
4. Check this guide again

**The system should start successfully now!**
