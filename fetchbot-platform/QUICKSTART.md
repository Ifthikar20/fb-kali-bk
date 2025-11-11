# FetchBot.ai - Quick Start Guide

## 🚀 One-Command Setup

```bash
./scripts/setup_and_run.sh
```

This script will:
1. ✅ Stop conflicting PostgreSQL services
2. ✅ Start Docker containers (PostgreSQL + Redis)
3. ✅ Create `.env` file if needed
4. ✅ Setup Python virtual environment
5. ✅ Install dependencies
6. ✅ Initialize database
7. ✅ Create admin user

## 📋 Prerequisites

- **Docker Desktop** installed and running
- **Python 3.10+** installed
- **Homebrew** (macOS) - optional

## 🔧 Manual Setup (If Script Fails)

### 1. Stop Conflicting Services

```bash
# Stop Homebrew PostgreSQL (if installed)
brew services stop postgresql@14

# Verify nothing is on port 5432
lsof -i :5432
```

### 2. Start Docker Infrastructure

```bash
# Start PostgreSQL and Redis
docker-compose -f docker-compose-multi-kali.yml up -d postgres redis

# Wait for services to be healthy
docker-compose -f docker-compose-multi-kali.yml ps
```

### 3. Create `.env` File

```bash
cp .env.example .env
```

**Edit `.env` and set these values:**

```bash
# IMPORTANT: Use localhost, not postgres!
DATABASE_URL=postgresql://fetchbot:fetchbot123@localhost:5432/fetchbot
REDIS_URL=redis://localhost:6379

# Get your API key from https://console.anthropic.com/
ANTHROPIC_API_KEY=sk-ant-api03-your-actual-key-here

# Enable dynamic containers
USE_DYNAMIC_AGENTS=true
```

### 4. Setup Python Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

### 5. Initialize Database

```bash
# Create tables
python -c "from models import init_db; init_db()"

# Create admin user
python scripts/create_admin_user.py
```

### 6. Build Kali Agent Image (For Dynamic Containers)

```bash
docker build -t fetchbot-kali-agent:latest -f kali-agent/Dockerfile kali-agent/
```

## ▶️ Run the Application

```bash
# Make sure venv is activated
source venv/bin/activate

# Run the server
python main.py
```

You should see:
```
[INIT] ✨ Using DYNAMIC MULTI-AGENT orchestrator (AI-driven agent creation)
```

## 🧪 Test Dynamic Containers

Watch containers spawn and cleanup automatically!

```bash
# In another terminal
watch -n 1 'docker ps --filter "label=managed_by=fetchbot-dynamic"'
```

**Login:** http://localhost:8000
- Username: `admin`
- Password: `admin123`

## 📞 Troubleshooting

See full guide in `DYNAMIC_CONTAINERS_SETUP.md`
