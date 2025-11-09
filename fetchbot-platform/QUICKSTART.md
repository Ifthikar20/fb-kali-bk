# FetchBot Dynamic Agent System - Quick Start

**Get up and running in 3 steps!**

---

## Step 1: Verify Setup ✅

Check that all components are in place:

```bash
./verify-setup.sh
```

**Expected output:**
```
✅ All checks passed! System is ready.
```

If you see errors, review the output and fix any missing files.

---

## Step 2: Create Environment File 🔧

```bash
./create-env.sh
```

This creates a `.env` file with required configuration.

**IMPORTANT:** Edit the file to add your Anthropic API key:

```bash
nano .env
```

Replace `sk-ant-api03-your-actual-key-here` with your real API key from https://console.anthropic.com/

**Your .env should have:**
```bash
ANTHROPIC_API_KEY=sk-ant-api03-xxxxx-your-real-key-xxxxx
USE_DYNAMIC_AGENTS=true
```

Save and exit (Ctrl+X, Y, Enter)

---

## Step 3: Start the System 🚀

**Build the containers:**
```bash
docker-compose build api --no-cache
```

This takes ~30-60 seconds. It installs all dependencies including jinja2 and email-validator.

**Start all services:**
```bash
docker-compose up -d
```

**Watch the logs:**
```bash
docker-compose logs -f api
```

**Look for this success message:**
```
[INIT] ✨ Using DYNAMIC MULTI-AGENT orchestrator (AI-driven agent creation)
INFO - Registered tool: create_agent (sandbox=False)
INFO - Registered tool: api_fuzzing (sandbox=True)
... (30+ tools)
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

## Test It Works! 🧪

**Check health:**
```bash
curl http://localhost:8000/health
# Should return: {"status":"healthy"}
```

**Open API docs:**
```bash
# In browser:
http://localhost:8000/docs
```

**Run complete test:**
```bash
chmod +x test-system.sh
./test-system.sh
```

---

## What's Different?

### OLD System (Fixed Bots):
```
User → API → Always runs 3 bots:
  • network-bot
  • ui-bot
  • db-bot
```

### NEW System (Dynamic Agents):
```
User → API → Root Coordinator Agent
         ↓
    Claude analyzes target
         ↓
    Creates specialized agents dynamically:
    • Recon Agent (discovers attack surface)
    • API Security Agent (if APIs found)
    • SQL Injection Agent (if database detected)
    • XSS Agent (if forms found)
    • ... whatever Claude decides is needed!
```

**Key Benefits:**
- ✅ Adaptive testing - different agents for different targets
- ✅ Specialized expertise - each agent has deep knowledge
- ✅ Efficient - only tests relevant attack vectors
- ✅ Intelligent - Claude makes all decisions

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `./verify-setup.sh` | Check all files are in place |
| `./create-env.sh` | Generate .env file template |
| `docker-compose build api --no-cache` | Rebuild API container |
| `docker-compose up -d` | Start all services |
| `docker-compose down` | Stop all services |
| `docker-compose logs -f api` | Watch API logs |
| `docker-compose ps` | Check container status |
| `curl http://localhost:8000/health` | Health check |

---

## Documentation

- **COMPLETE_SETUP_GUIDE.md** - Detailed setup with troubleshooting
- **DYNAMIC_AGENT_USAGE.md** - How the agent system works
- **DYNAMIC_ARCHITECTURE_PLAN.md** - Technical architecture details
- **IMPLEMENTATION_SUMMARY.md** - What was built

---

## Troubleshooting

**Container keeps restarting?**
```bash
docker-compose logs api --tail=50
```

Common causes:
1. Missing ANTHROPIC_API_KEY → Add to .env
2. Invalid API key → Check at console.anthropic.com
3. Missing dependencies → Rebuild with --no-cache

**Can't connect to API?**
```bash
docker-compose ps | grep api
# Should show "Up", not "Restarting"
```

**Need help?**
See COMPLETE_SETUP_GUIDE.md for detailed troubleshooting.

---

## What Happens When You Start a Scan?

1. **You call the API:**
   ```bash
   POST /scan
   {
     "target": "http://example.com",
     "organization_id": 1
   }
   ```

2. **Root Coordinator starts:**
   - Analyzes target
   - Creates Reconnaissance Agent
   - Waits for recon results

3. **Recon Agent discovers:**
   - API endpoints at `/api/*`
   - Login form at `/login`
   - MySQL database detected

4. **Root creates specialized agents:**
   - API Security Agent (api_testing module)
   - SQL Injection Agent (sql_injection module)
   - XSS Agent (xss module)

5. **Each agent runs independently:**
   - API agent finds exposed .env vars → CRITICAL finding
   - SQL agent finds injection → HIGH finding
   - XSS agent finds nothing → completes quickly

6. **Root aggregates results:**
   ```json
   {
     "status": "completed",
     "total_findings": 2,
     "critical_findings": 1,
     "high_findings": 1,
     "agents_created": [
       {"name": "Recon Agent", "status": "completed"},
       {"name": "API Security Agent", "findings": 1},
       {"name": "SQL Injection Agent", "findings": 1},
       {"name": "XSS Agent", "findings": 0}
     ]
   }
   ```

**All decisions made by Claude AI - zero hardcoding!** 🚀

---

**Ready to test? Run `./verify-setup.sh` then `./create-env.sh`!**
