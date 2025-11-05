# 🐉 FetchBot.ai - Multi-Kali Container Setup

## 🎯 Two Architecture Options

FetchBot.ai now supports **TWO deployment architectures**:

### Option 1: **Multiple Kali Containers** (Recommended) ⭐

```
┌──────────────────────────────────────────────────┐
│         FetchBot.ai Multi-Kali Platform          │
├──────────────────────────────────────────────────┤
│                                                   │
│  ┌─────────────┐         ┌──────────┐           │
│  │  Orchestrator│────────▶│PostgreSQL│           │
│  │  + Claude AI │         └──────────┘           │
│  └──────┬──────┘                                 │
│         │                                         │
│         │  Distributes Tasks                     │
│         │                                         │
│    ┌────┴─────┬─────────┬─────────┬──────┐     │
│    │          │         │         │      │     │
│  ┌─▼──┐    ┌─▼──┐   ┌──▼─┐   ┌──▼─┐   ...    │
│  │Kali│    │Kali│   │Kali│   │Kali│           │
│  │ 1  │    │ 2  │   │ 3  │   │ N  │           │
│  └────┘    └────┘   └────┘   └────┘           │
│                                                   │
│  Each Kali has ALL tools:                        │
│  - nmap, masscan, nikto, sqlmap, dirb           │
│  - Full Kali Linux toolset                       │
│                                                   │
└──────────────────────────────────────────────────┘
```

**Pros:**
- ✅ **Scalable**: Easily add more Kali containers
- ✅ **Parallel**: Scan multiple targets simultaneously
- ✅ **Full Toolset**: Each container has complete Kali Linux
- ✅ **Realistic**: Mimics real pentesting environment
- ✅ **Flexible**: Claude AI distributes tasks intelligently

**Use When:**
- Testing multiple targets
- Need parallel scanning
- Want realistic attack simulation
- Have sufficient resources

---

### Option 2: **Specialized Bots** (Original)

```
┌──────────────────────────────────────────────────┐
│       FetchBot.ai Specialized Bots Platform       │
├──────────────────────────────────────────────────┤
│                                                   │
│  ┌─────────────┐         ┌──────────┐           │
│  │ Orchestrator│────────▶│PostgreSQL│           │
│  │  + Claude AI │         └──────────┘           │
│  └──────┬──────┘                                 │
│         │                                         │
│         │  Decides Which Bot                     │
│         │                                         │
│    ┌────┴─────┬──────────┬──────────┐           │
│    │          │          │          │           │
│  ┌─▼──────┐ ┌▼────────┐ ┌▼───────┐             │
│  │Network │ │ UI/Web  │ │Database│             │
│  │  Bot   │ │  Bot    │ │  Bot   │             │
│  └────────┘ └─────────┘ └────────┘             │
│                                                   │
│  Specialized:                                     │
│  - Network: nmap only                            │
│  - Web: nikto, XSS testing                       │
│  - Database: sqlmap only                         │
│                                                   │
└──────────────────────────────────────────────────┘
```

**Pros:**
- ✅ **Lightweight**: Smaller containers
- ✅ **Focused**: Each bot specialized
- ✅ **Fast**: Quick to build and start

**Use When:**
- Limited resources
- Single target testing
- Don't need full Kali environment

---

## 🚀 Quick Start: Multi-Kali Setup

### Prerequisites
- Docker & Docker Compose
- 4GB+ RAM (2GB per Kali container recommended)
- Anthropic API key

### Step 1: Configure Environment

```bash
cd fetchbot-platform
nano .env
```

Add your Anthropic API key:
```bash
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

### Step 2: Build and Start (Multi-Kali)

```bash
# Build all containers
docker-compose -f docker-compose-multi-kali.yml build

# Start with 3 Kali agents (default)
docker-compose -f docker-compose-multi-kali.yml up -d

# Check status
docker-compose -f docker-compose-multi-kali.yml ps
```

### Step 3: Verify

```bash
# Check API
curl http://localhost:8000/health

# Check Kali agents
curl http://localhost:9001/health  # Kali Agent 1
curl http://localhost:9002/health  # Kali Agent 2
curl http://localhost:9003/health  # Kali Agent 3
```

---

## ⚙️ Scaling Kali Containers

### Add More Agents On-The-Fly

Want 5 Kali containers instead of 3? Easy!

**Method 1: Edit docker-compose**

Add more kali-agent entries in `docker-compose-multi-kali.yml`:

```yaml
# Kali Agent 4
kali-agent-4:
  build:
    context: ./kali-agent
  container_name: kali-agent-4
  environment:
    - AGENT_ID=kali-agent-4
    - AGENT_PORT=9000
  ports:
    - "9004:9000"
  # ... same config as other agents
```

Then update the API environment:
```yaml
api:
  environment:
    - NUM_KALI_AGENTS=4  # <-- Update this
```

**Method 2: Docker Compose Scale** (Advanced)

```bash
# This requires removing container_name from kali-agent services
docker-compose -f docker-compose-multi-kali.yml up --scale kali-agent=5 -d
```

---

## 🎯 Usage: Multi-Kali vs Specialized

### Multi-Kali Approach

```bash
# Create organization
curl -X POST http://localhost:8000/api/organizations \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Acme Corp",
    "admin_email": "admin@acme.com"
  }'

# Start scan - Claude distributes across Kali containers
curl -X POST http://localhost:8000/api/pentest \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Multi-Kali Scan",
    "target": "example.com",
    "mode": "discovery"
  }'
```

**What Happens:**
1. Claude AI plans the attack strategy
2. Tasks distributed to Kali Agent 1, 2, 3 in parallel
3. All agents scan simultaneously
4. Claude analyzes findings and decides next steps
5. More targeted scans if needed
6. Final comprehensive report

### Specialized Bots Approach

```bash
# Use original docker-compose.yml
docker-compose up -d

# Scan works the same way
curl -X POST http://localhost:8000/api/pentest \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Specialized Scan",
    "target": "example.com"
  }'
```

**What Happens:**
1. Claude decides to run Network Bot first
2. Network Bot scans ports
3. Claude reviews, decides to run Web Bot
4. Web Bot scans for XSS
5. Claude reviews, decides to run DB Bot
6. DB Bot tests SQL injection
7. Final report

---

## 📊 Comparison

| Feature | Multi-Kali | Specialized Bots |
|---------|------------|------------------|
| **Containers** | 3-10 Kali | 3 specialized |
| **RAM Usage** | 6-20GB | 2-4GB |
| **Build Time** | ~10-15 min | ~5 min |
| **Scan Speed** | **Faster (parallel)** | Sequential |
| **Toolset** | Full Kali | Limited |
| **Scalability** | Excellent | Limited |
| **Use Case** | Multiple targets | Single target |

---

## 💡 Recommended Setup

### For Development/Testing
```bash
# Use specialized bots (lightweight)
docker-compose up -d
```

### For Production/Real Pentesting
```bash
# Use multi-Kali (powerful)
docker-compose -f docker-compose-multi-kali.yml up -d
```

### For Large-Scale Scanning
```bash
# Multi-Kali with 5+ agents
# Edit docker-compose-multi-kali.yml to add more agents
docker-compose -f docker-compose-multi-kali.yml up -d
```

---

## 🔧 Troubleshooting

### Kali Containers Won't Start

**Issue**: Containers exit immediately or won't build

**Solution**:
```bash
# Check logs
docker-compose -f docker-compose-multi-kali.yml logs kali-agent-1

# Rebuild from scratch
docker-compose -f docker-compose-multi-kali.yml build --no-cache kali-agent-1

# Check if nmap/nikto work inside container
docker exec -it kali-agent-1 nmap --version
```

### Not Enough Memory

**Issue**: System running out of RAM with multiple Kali containers

**Solution**:
```bash
# Reduce number of agents
# Edit docker-compose-multi-kali.yml
# Remove kali-agent-3, kali-agent-4, etc.
# Update NUM_KALI_AGENTS=2 in API environment
```

### Scans Failing

**Issue**: Scans timeout or return errors

**Solution**:
```bash
# Test individual agent
curl -X POST http://localhost:9001/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "scanme.nmap.org",
    "scan_type": "network",
    "depth": "quick"
  }'

# Check if target is reachable from container
docker exec -it kali-agent-1 ping -c 3 example.com
```

---

## 🎓 Advanced: Custom Kali Containers

Want to add your own tools to Kali containers?

Edit `kali-agent/Dockerfile`:

```dockerfile
# Add after line with "Install essential security tools"
RUN apt-get install -y \
    # Your custom tools
    metasploit-framework \
    burpsuite \
    john \
    hydra \
    && rm -rf /var/lib/apt/lists/*
```

Then rebuild:
```bash
docker-compose -f docker-compose-multi-kali.yml build kali-agent-1
```

---

## 📈 Performance Tips

1. **RAM**: Allocate 2GB per Kali container
2. **CPUs**: Give Docker access to all CPU cores
3. **Parallel**: Use multi-Kali for parallel scanning
4. **Quick Scans**: Use `depth: quick` for initial reconnaissance
5. **Deep Scans**: Use `depth: deep` only when needed

---

## ✨ Summary

**Choose Multi-Kali when:**
- You need parallel scanning
- Testing multiple targets
- Want full Kali toolset
- Have 8GB+ RAM

**Choose Specialized Bots when:**
- Limited resources (4GB RAM)
- Single target testing
- Quick development/testing

**Both architectures use Claude AI for intelligent orchestration!** 🧠

---

**Next Steps:**
- See `README.md` for general usage
- See `SETUP.md` for environment configuration
- See `docker-compose-multi-kali.yml` for multi-Kali setup
- See `docker-compose.yml` for specialized bots setup

---

**Questions?** Check the main README or open an issue!
