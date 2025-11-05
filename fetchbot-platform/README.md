# 🤖 FetchBot.ai - AI-Powered Container Attack Simulator

> **Advanced security testing platform with Claude AI-powered orchestration and specialized scanning agents**

FetchBot.ai is an intelligent penetration testing platform that uses containerized attack agents and Claude AI to automatically discover, analyze, and report security vulnerabilities. Each scanning agent operates independently while Claude orchestrates their activities based on findings, creating an adaptive and efficient security testing workflow.

---

## 🎯 Key Features

### 🧠 Claude AI Orchestration
- **Intelligent Decision Making**: Claude analyzes findings in real-time and decides which scanners to run next
- **Adaptive Scanning**: Automatically adjusts scanning strategy based on discovered vulnerabilities
- **Professional Reporting**: AI-generated executive summaries and detailed technical reports

### 🔍 Specialized Scanning Agents

#### 1. **Network Bot** (Port 8002)
- Port scanning with nmap
- Service version detection
- OS fingerprinting
- Subdomain enumeration
- DNS reconnaissance

#### 2. **UI/Web Bot** (Port 8001)
- XSS (Cross-Site Scripting) detection
- CSRF vulnerability testing
- Security header analysis
- Directory enumeration
- Sensitive file discovery
- Technology stack detection
- Nikto web scanning integration

#### 3. **DB Bot** (Port 8003)
- SQL injection testing (error-based, boolean-based, time-based)
- NoSQL injection detection
- Database error disclosure
- Authentication bypass testing
- SQLMap integration

### 📊 Advanced Reporting
- **HTML Reports**: Professional, color-coded security reports
- **JSON Reports**: Machine-readable data for integration
- **Markdown Reports**: Documentation-friendly format
- **Real-time Analysis**: Claude provides ongoing security assessment

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     FetchBot.ai Platform                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐         ┌─────────────────┐              │
│  │   FastAPI    │────────▶│  PostgreSQL DB  │              │
│  │     API      │         │  (Findings)     │              │
│  └──────┬───────┘         └─────────────────┘              │
│         │                                                    │
│         │                  ┌─────────────────┐              │
│         │                  │   Claude AI     │              │
│         ├─────────────────▶│  Orchestrator   │              │
│         │                  │  (Decision)     │              │
│         │                  └─────────────────┘              │
│         │                                                    │
│         │      ┌──────────────┬──────────────┬────────────┐│
│         │      │              │              │            ││
│    ┌────▼────┐ │  ┌────────┐ │  ┌────────┐ │ ┌────────┐ ││
│    │ Network │ │  │   UI   │ │  │   DB   │ │ │ Report │ ││
│    │   Bot   │ │  │  Bot   │ │  │  Bot   │ │  Generator││
│    └─────────┘ │  └────────┘ │  └────────┘ │ └────────┘ ││
│                │              │              │            ││
│                └──────────────┴──────────────┴────────────┘│
│                      Containerized Agents                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Anthropic API key (for Claude AI)
- AWS credentials (optional, for EC2 deployment)

### 1. Clone and Setup

```bash
git clone <repository-url>
cd fb-kali-bk/fetchbot-platform
```

### 2. Configure Environment

Create or edit `.env` file:

```bash
# Platform Configuration
PLATFORM_NAME=FetchBot.ai
ADMIN_EMAIL=admin@fetchbot.ai

# Database
DATABASE_URL=postgresql://fetchbot:fetchbot123@postgres:5432/fetchbot

# Redis
REDIS_URL=redis://redis:6379

# Claude AI (REQUIRED)
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# AWS (Optional - for EC2 deployment)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret

# Security
JWT_SECRET=change_this_to_random_64_character_string
```

### 3. Build and Start

```bash
# Build all containers
docker-compose build

# Start all services
docker-compose up -d

# Check status
docker-compose ps
```

### 4. Verify Installation

```bash
# Check API health
curl http://localhost:8000/health

# Check bots
curl http://localhost:8001/health  # UI Bot
curl http://localhost:8002/health  # Network Bot
curl http://localhost:8003/health  # DB Bot
```

---

## 📖 Usage Guide

### Creating an Organization

```bash
curl -X POST http://localhost:8000/api/organizations \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Acme Corporation",
    "admin_email": "admin@acme.com",
    "allowed_targets": ["example.com"]
  }'
```

**Response:**
```json
{
  "id": "org-uuid",
  "name": "Acme Corporation",
  "api_key": "fb_live_...",
  "elastic_ip": "x.x.x.x",
  "ec2_instance_id": "i-..."
}
```

**💡 Save the API key!** You'll need it for all subsequent requests.

### Starting a Security Scan

```bash
curl -X POST http://localhost:8000/api/pentest \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Production Security Audit",
    "target": "example.com",
    "mode": "discovery"
  }'
```

**What Happens:**

1. **Claude Planning Phase**: AI analyzes the target and decides which scanners to run first
2. **Initial Reconnaissance**: Selected bots perform quick scans
3. **Iterative Analysis**: Claude reviews findings and determines next steps
4. **Deep Scanning**: Based on findings, Claude may trigger deeper scans
5. **Final Analysis**: Claude generates comprehensive security report

### Monitoring Scan Progress

```bash
# Get scan status
curl http://localhost:8000/api/pentest/{job_id} \
  -H 'Authorization: Bearer YOUR_API_KEY'

# Get findings
curl http://localhost:8000/api/pentest/{job_id}/findings \
  -H 'Authorization: Bearer YOUR_API_KEY'
```

### Generating Reports

```bash
# HTML Report (professional, color-coded)
curl http://localhost:8000/api/pentest/{job_id}/report/html \
  -H 'Authorization: Bearer YOUR_API_KEY' > report.html

# JSON Report (machine-readable)
curl http://localhost:8000/api/pentest/{job_id}/report/json \
  -H 'Authorization: Bearer YOUR_API_KEY' > report.json

# Markdown Report (documentation-friendly)
curl http://localhost:8000/api/pentest/{job_id}/report/markdown \
  -H 'Authorization: Bearer YOUR_API_KEY' > report.md
```

---

## 🎯 Scanning Modes

### Quick Scan (Default)
- Fast reconnaissance
- Top 1000 ports
- Basic vulnerability checks
- ~5-10 minutes

### Full Scan
- Comprehensive port scan (all 65535 ports)
- Service version detection
- Deep web crawling
- Advanced SQL injection testing
- ~30-60 minutes

### Example: Full Scan
```bash
curl -X POST http://localhost:8000/api/pentest \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Comprehensive Security Audit",
    "target": "example.com",
    "mode": "full"
  }'
```

---

## 🧪 Testing Individual Bots

### Network Bot

```bash
curl -X POST http://localhost:8002/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "example.com",
    "scan_type": "quick"
  }'
```

### UI Bot

```bash
curl -X POST http://localhost:8001/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "example.com",
    "scan_type": "quick"
  }'
```

### DB Bot

```bash
curl -X POST http://localhost:8003/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "example.com",
    "scan_type": "quick"
  }'
```

---

## 🛠️ Development

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f network-bot
docker-compose logs -f ui-bot
docker-compose logs -f db-bot
docker-compose logs -f api
```

### Rebuild After Changes

```bash
# Rebuild specific bot
docker-compose build network-bot
docker-compose up -d network-bot

# Rebuild all
docker-compose build
docker-compose up -d
```

### Database Access

```bash
# Connect to PostgreSQL
docker exec -it fetchbot-postgres psql -U fetchbot -d fetchbot

# View organizations
SELECT id, name, elastic_ip FROM organizations;

# View scan jobs
SELECT id, name, target, status FROM pentest_jobs;
```

---

## 📊 API Documentation

Once running, visit:

**Swagger UI**: http://localhost:8000/docs

**ReDoc**: http://localhost:8000/redoc

### Main Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/organizations` | POST | Create new organization |
| `/api/organizations/me` | GET | Get organization details |
| `/api/pentest` | POST | Start new scan |
| `/api/pentest/{id}` | GET | Get scan status |
| `/api/pentest/{id}/findings` | GET | Get scan findings |
| `/api/pentest/{id}/report/{format}` | GET | Generate report (html/json/markdown) |

---

## 🔒 Security & Compliance

### ⚠️ Important Usage Guidelines

1. **Authorization Required**: Only scan systems you own or have explicit written permission to test
2. **Legal Compliance**: Unauthorized security testing is illegal in most jurisdictions
3. **Responsible Disclosure**: Report findings responsibly to system owners
4. **Rate Limiting**: Respect target systems and avoid DoS conditions
5. **Data Privacy**: Handle discovered vulnerabilities and data with care

### Intended Use Cases

✅ **Authorized Uses:**
- Internal security audits
- Authorized penetration testing engagements
- CTF (Capture The Flag) competitions
- Security research with permission
- Educational purposes on owned infrastructure

❌ **Prohibited Uses:**
- Scanning systems without authorization
- Malicious hacking or data theft
- Denial of Service attacks
- Any illegal activities

---

## 🐛 Troubleshooting

### Bots Won't Start

```bash
# Check Docker logs
docker-compose logs network-bot

# Verify network connectivity
docker network inspect fetchbot-platform_fetchbot

# Rebuild bot
docker-compose build network-bot
docker-compose up -d network-bot
```

### Claude AI Not Working

- Verify `ANTHROPIC_API_KEY` in `.env`
- Check API quota/limits
- View orchestrator logs: `docker-compose logs api`

### Database Connection Issues

```bash
# Restart database
docker-compose restart postgres

# Check connection
docker exec -it fetchbot-postgres pg_isready -U fetchbot
```

---

## 📈 Performance Tips

1. **Parallel Scanning**: Claude automatically runs independent scans in parallel
2. **Scan Scope**: Use `quick` mode for initial assessment, `full` for deep analysis
3. **Resource Limits**: Adjust Docker resource limits for large-scale scans
4. **Caching**: Results are cached in PostgreSQL for fast retrieval

---

## 🤝 Contributing

We welcome contributions! Areas for improvement:

- Additional scanning bots (e.g., SSL/TLS testing, API security)
- Enhanced AI prompts for better decision-making
- More vulnerability detection patterns
- Integration with other security tools

---

## 📄 License

This tool is for **authorized security testing only**. Users are responsible for compliance with all applicable laws and regulations.

---

## 🆘 Support

- **Issues**: Open a GitHub issue
- **Email**: admin@fetchbot.ai
- **Documentation**: See `/docs` folder

---

## 🙏 Acknowledgments

- **Claude AI** by Anthropic for intelligent orchestration
- **nmap** for network scanning
- **Nikto** for web vulnerability scanning
- **SQLMap** for SQL injection testing

---

**Built with ❤️ for security professionals**

Last Updated: 2025-11-05
