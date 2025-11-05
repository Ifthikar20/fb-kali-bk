# FetchBot.ai - Deployment Guide
## Running Docker Containers with Kali Linux

You have **two deployment options**:

---

## Option A: Local Multi-Kali Setup (Recommended for Testing)

Run 3 Kali Linux containers locally with Docker.

### Prerequisites
- Docker and Docker Compose installed
- At least 4GB RAM available
- ANTHROPIC_API_KEY configured in `.env`

### Step 1: Verify Configuration

Ensure your `.env` file has the required settings:

```bash
cd /home/user/fb-kali-bk/fetchbot-platform
cat .env | grep -E "(ANTHROPIC_API_KEY|DATABASE_URL|REDIS_URL)"
```

**Required variables:**
- `ANTHROPIC_API_KEY` - Your complete Anthropic API key
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string

### Step 2: Build and Start Kali Containers

```bash
cd /home/user/fb-kali-bk/fetchbot-platform

# Build all containers (first time: 10-15 minutes)
docker compose -f docker-compose-multi-kali.yml build

# Start all services
docker compose -f docker-compose-multi-kali.yml up -d

# Check status
docker compose -f docker-compose-multi-kali.yml ps
```

### Step 3: Verify All Services

```bash
# Check API server (port 8000)
curl http://localhost:8000/health

# Check Kali Agent 1 (port 9001)
curl http://localhost:9001/health

# Check Kali Agent 2 (port 9002)
curl http://localhost:9002/health

# Check Kali Agent 3 (port 9003)
curl http://localhost:9003/health

# Check PostgreSQL
docker exec fetchbot-postgres pg_isready -U fetchbot

# Check Redis
docker exec fetchbot-redis redis-cli ping
```

**Expected Responses:**
- API: `{"status":"healthy","platform":"FetchBot.ai"}`
- Kali Agents: `{"status":"healthy","agent":"kali-agent","agent_id":"kali-agent-X"}`
- PostgreSQL: `ready`
- Redis: `PONG`

### Step 4: View Logs

```bash
# All services
docker compose -f docker-compose-multi-kali.yml logs -f

# Specific service
docker compose -f docker-compose-multi-kali.yml logs -f api
docker compose -f docker-compose-multi-kali.yml logs -f kali-agent-1
```

### Step 5: Test a Scan

```bash
# Create an organization (no AWS needed for local mode)
# Note: In local mode, EC2 creation will be skipped
curl -X POST http://localhost:8000/api/organizations \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Test Corp",
    "admin_email": "admin@test.com"
  }'

# Save the API key from response
export API_KEY="fb_live_xxxxx"

# Run a test scan (use a test target you own)
curl -X POST http://localhost:8000/api/pentest \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Test Scan",
    "target": "scanme.nmap.org",
    "mode": "discovery"
  }'
```

### Architecture (Local Mode)

```
┌─────────────────────────────────────────────────────────┐
│                   Your Local Machine                     │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐          │
│  │PostgreSQL│    │  Redis   │    │   API    │          │
│  │  :5432   │    │  :6379   │    │  :8000   │          │
│  └──────────┘    └──────────┘    └────┬─────┘          │
│                                        │                 │
│         ┌──────────────────────────────┼────────┐       │
│         │                              │        │       │
│  ┌──────▼──────┐  ┌──────▼──────┐  ┌──▼───────▼──┐    │
│  │ Kali Agent 1│  │ Kali Agent 2│  │ Kali Agent 3│    │
│  │   :9001     │  │   :9002     │  │   :9003     │    │
│  │             │  │             │  │             │    │
│  │ nmap,nikto, │  │ nmap,nikto, │  │ nmap,nikto, │    │
│  │ sqlmap, etc │  │ sqlmap, etc │  │ sqlmap, etc │    │
│  └─────────────┘  └─────────────┘  └─────────────┘    │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

### Stopping Services

```bash
# Stop all containers
docker compose -f docker-compose-multi-kali.yml down

# Stop and remove volumes (WARNING: deletes database)
docker compose -f docker-compose-multi-kali.yml down -v
```

---

## Option B: AWS EC2 with Kali Linux Containers

Deploy a dedicated EC2 instance with Kali Linux containers.

### Prerequisites
- AWS Account with EC2 access
- AWS Access Key ID and Secret Access Key
- AWS CLI installed
- SSH key pair created in AWS

### Step 1: Configure AWS Credentials

Edit `.env` file and add your AWS credentials:

```bash
cd /home/user/fb-kali-bk/fetchbot-platform
nano .env
```

**Update these values:**
```bash
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_KEY_PAIR_NAME=your-key-pair-name
```

### Step 2: Deploy EC2 Instance

```bash
cd /home/user/fb-kali-bk/fetchbot-platform

# Make script executable
chmod +x deploy-ec2-kali.sh

# Run deployment
./deploy-ec2-kali.sh
```

**The script will:**
1. Create security group with necessary ports (22, 8000, 9001-9003)
2. Launch EC2 instance (Ubuntu with Docker)
3. Install Docker and pull Kali Linux images
4. Start 3 Kali containers on ports 9001-9003
5. Display instance details and access information

### Step 3: Verify Deployment

After 5-10 minutes (for Docker setup to complete):

```bash
# SSH into instance
ssh ubuntu@<PUBLIC_IP>

# Check Docker containers
sudo docker ps

# Test Kali agents
curl http://localhost:9001/health
curl http://localhost:9002/health
curl http://localhost:9003/health
```

### Step 4: Access Remotely

From your local machine:

```bash
# Replace <PUBLIC_IP> with your instance IP
curl http://<PUBLIC_IP>:9001/health
curl http://<PUBLIC_IP>:9002/health
curl http://<PUBLIC_IP>:9003/health
```

### Architecture (EC2 Mode)

```
┌─────────────────────────────────────────────────────────┐
│                    AWS EC2 Instance                      │
│                  (Public IP: x.x.x.x)                    │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────────────────────────────────────┐           │
│  │         Docker Compose Network            │           │
│  │                                            │           │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────▼──────┐   │
│  │  │Kali Agent 1 │  │Kali Agent 2 │  │Kali Agent 3│   │
│  │  │  Port 9001  │  │  Port 9002  │  │  Port 9003 │   │
│  │  │             │  │             │  │            │   │
│  │  │ - nmap      │  │ - nmap      │  │ - nmap     │   │
│  │  │ - nikto     │  │ - nikto     │  │ - nikto    │   │
│  │  │ - sqlmap    │  │ - sqlmap    │  │ - sqlmap   │   │
│  │  │ - masscan   │  │ - masscan   │  │ - masscan  │   │
│  │  └─────────────┘  └─────────────┘  └────────────┘   │
│  │                                                        │
│  └────────────────────────────────────────────────────── │
│                                                           │
└─────────────────────────────────────────────────────────┘
                           ▲
                           │
                           │ Internet
                           │
          ┌────────────────┴──────────────────┐
          │  Your Local Machine (API Server)  │
          │  Orchestrates Kali Agents         │
          └───────────────────────────────────┘
```

### Managing EC2 Instance

```bash
# Get instance status
aws ec2 describe-instances \
  --region us-east-1 \
  --instance-ids i-xxxxxxxxx

# Stop instance (save costs)
aws ec2 stop-instances \
  --region us-east-1 \
  --instance-ids i-xxxxxxxxx

# Start instance
aws ec2 start-instances \
  --region us-east-1 \
  --instance-ids i-xxxxxxxxx

# Terminate instance (DELETE)
aws ec2 terminate-instances \
  --region us-east-1 \
  --instance-ids i-xxxxxxxxx
```

---

## Kali Agent Capabilities

Each Kali agent has these security tools installed:

### Network Scanning
- **nmap** - Port scanning, service detection, OS fingerprinting
- **masscan** - Fast port scanner
- **dnsutils** - DNS enumeration
- **netcat** - Network connections

### Web Scanning
- **nikto** - Web vulnerability scanner
- **dirb** - Directory/file brute forcing
- **whatweb** - Web technology detection
- **curl/wget** - HTTP testing

### Database Testing
- **sqlmap** - SQL injection automation

### Testing Individual Agents

```bash
# Network scan
curl -X POST http://localhost:9001/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "scanme.nmap.org",
    "scan_type": "network",
    "depth": "quick"
  }'

# Web scan
curl -X POST http://localhost:9002/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "example.com",
    "scan_type": "web",
    "depth": "quick"
  }'

# Database scan
curl -X POST http://localhost:9003/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "example.com",
    "scan_type": "database",
    "depth": "quick"
  }'
```

---

## Troubleshooting

### Docker Issues

```bash
# Check Docker is running
systemctl status docker

# Restart Docker
sudo systemctl restart docker

# Clean up old containers
docker system prune -a
```

### Port Conflicts

```bash
# Check what's using a port
netstat -tlnp | grep 8000
lsof -i :8000

# Kill process
kill -9 <PID>
```

### Kali Agent Not Responding

```bash
# Rebuild agent
docker compose -f docker-compose-multi-kali.yml build kali-agent-1

# Restart agent
docker compose -f docker-compose-multi-kali.yml restart kali-agent-1

# Check logs
docker logs kali-agent-1
```

### AWS EC2 Issues

```bash
# Can't SSH to instance
# - Check security group has port 22 open
# - Verify you're using correct key pair
# - Check instance is in 'running' state

# Check user data logs (setup script)
ssh ubuntu@<IP> 'sudo cat /var/log/cloud-init-output.log'
```

---

## Security Notes

⚠️ **IMPORTANT**:
1. Only scan targets you own or have written permission to test
2. Keep your ANTHROPIC_API_KEY secure
3. Don't expose Kali agents to public internet without authentication
4. Terminate EC2 instances when not in use to avoid charges
5. Use strong SSH keys for EC2 access

---

## Cost Estimation (EC2)

**t3.medium instance (recommended):**
- ~$0.0416/hour = ~$30/month if running 24/7
- Stop when not in use to save costs
- Storage: ~$1-2/month (30GB)

**Optimization:**
- Use t3.small for light workloads (~$15/month)
- Use Spot Instances for testing (~70% discount)
- Set up auto-shutdown scripts

---

## Next Steps

1. **Local Testing**: Start with Option A to test the platform
2. **Production**: Use Option B for dedicated scanning infrastructure
3. **Integration**: Connect your application to the API
4. **Monitoring**: Set up CloudWatch for EC2 monitoring
5. **Scaling**: Add more Kali agents as needed

For more details, see the main [README.md](README.md)
