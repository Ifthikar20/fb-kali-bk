# AWS Deployment Guide for FetchBot.ai Multi-Kali Setup

This guide explains how to deploy FetchBot.ai with multiple Kali Linux containers on AWS.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Local Multi-Kali Setup](#local-multi-kali-setup)
3. [AWS EC2 Deployment](#aws-ec2-deployment)
4. [Architecture Overview](#architecture-overview)

---

## Prerequisites

### Required
- Docker and Docker Compose installed
- Anthropic API key (get from https://console.anthropic.com/)
- Python 3.11+ (for local development)

### For AWS Deployment
- AWS account with appropriate permissions
- AWS CLI configured
- VPC with public subnet
- Security group with required ports open
- EC2 key pair

---

## Local Multi-Kali Setup

This is the setup you're currently running - multiple Kali Linux containers on your local machine.

### Step 1: Configure Environment Variables

Create a `.env` file in the `fetchbot-platform` directory:

```bash
cd fetchbot-platform
cp .env.example .env
```

Edit `.env` and set the **required** values:

```bash
# REQUIRED - Must set these
ANTHROPIC_API_KEY=sk-ant-xxxxx  # Get from https://console.anthropic.com/

# Database and Redis (already configured for docker-compose)
DATABASE_URL=postgresql://fetchbot:fetchbot123@postgres:5432/fetchbot
REDIS_URL=redis://redis:6379

# Security
JWT_SECRET=your_random_64_character_string_here

# Platform
PLATFORM_NAME=FetchBot.ai
ADMIN_EMAIL=admin@fetchbot.ai
```

**IMPORTANT**: The `ANTHROPIC_API_KEY` is required. Get your API key from:
https://console.anthropic.com/settings/keys

### Step 2: Build and Start Containers

```bash
# Build the Docker images
docker-compose -f docker-compose-multi-kali.yml build

# Start all containers
docker-compose -f docker-compose-multi-kali.yml up -d
```

This will start:
- **3 Kali Linux agents** (ports 9001, 9002, 9003)
- **PostgreSQL database** (port 5432)
- **Redis** (port 6379)
- **FetchBot API** (port 8000)

### Step 3: Verify Containers Are Running

```bash
# Check container status
docker-compose -f docker-compose-multi-kali.yml ps

# Check API health
curl http://localhost:8000/health

# Expected response:
# {"status":"healthy","platform":"FetchBot.ai"}
```

### Step 4: View Logs

```bash
# View all logs
docker-compose -f docker-compose-multi-kali.yml logs -f

# View API logs only
docker logs fetchbot-api -f

# View Kali agent logs
docker logs kali-agent-1 -f
```

### Troubleshooting Local Setup

If the API container keeps restarting:

1. **Check if .env file exists**:
   ```bash
   ls -la .env
   ```

2. **Verify ANTHROPIC_API_KEY is set**:
   ```bash
   grep ANTHROPIC_API_KEY .env
   ```

3. **Check API container logs**:
   ```bash
   docker logs fetchbot-api
   ```

4. **Common issues**:
   - Missing `ANTHROPIC_API_KEY` → Add to `.env` file
   - Invalid API key → Check key is correct in `.env`
   - Database not ready → Wait for postgres container to be healthy

---

## AWS EC2 Deployment

For production deployment, you can run the API on AWS EC2 with dedicated infrastructure for each organization.

### Architecture

- **API Server**: Runs on EC2 instance with the multi-Kali orchestrator
- **Kali Agents**: Run as Docker containers on the same EC2 instance
- **Per-Organization EC2**: Each organization gets a dedicated EC2 instance with Elastic IP
- **Database**: PostgreSQL (can use RDS for production)
- **Redis**: ElastiCache or self-hosted

### Step 1: AWS Prerequisites

1. **Create VPC and Subnet**:
   - VPC with CIDR block (e.g., 10.0.0.0/16)
   - Public subnet with internet gateway
   - Route table configured for internet access

2. **Create Security Group**:
   ```bash
   # Allow inbound traffic
   - Port 22 (SSH) - from your IP only
   - Port 8000 (API) - from your IP or load balancer
   - Port 9001-9010 (Kali agents) - internal only
   - Port 5432 (PostgreSQL) - internal only
   - Port 6379 (Redis) - internal only
   ```

3. **Create EC2 Key Pair**:
   ```bash
   aws ec2 create-key-pair --key-name fetchbot-key \
     --query 'KeyMaterial' --output text > fetchbot-key.pem
   chmod 400 fetchbot-key.pem
   ```

4. **Create S3 Bucket** (for evidence storage):
   ```bash
   aws s3 mb s3://fetchbot-evidence-YOURNAME
   ```

### Step 2: Configure AWS Environment Variables

Edit `.env` and add AWS configuration:

```bash
# AWS Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=your_secret_access_key

# AWS VPC Configuration
AWS_VPC_ID=vpc-xxxxx
AWS_SUBNET_ID=subnet-xxxxx
AWS_SECURITY_GROUP_ID=sg-xxxxx

# AWS Key Pair
AWS_KEY_PAIR_NAME=fetchbot-key

# AWS S3 Bucket
AWS_S3_BUCKET=fetchbot-evidence-YOURNAME

# EC2 Bot Configuration
BOT_AMI_ID=ami-0c55b159cbfafe1f0  # Ubuntu 22.04 LTS in us-east-1
BOT_INSTANCE_TYPE=t3.medium
```

### Step 3: Launch EC2 Instance for API Server

#### Option A: Manual EC2 Setup

```bash
# Launch EC2 instance
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.medium \
  --key-name fetchbot-key \
  --security-group-ids sg-xxxxx \
  --subnet-id subnet-xxxxx \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=fetchbot-api-server}]'

# SSH into instance
ssh -i fetchbot-key.pem ubuntu@<EC2_PUBLIC_IP>

# On EC2 instance, install Docker
sudo apt-get update
sudo apt-get install -y docker.io docker-compose git
sudo systemctl start docker
sudo usermod -aG docker ubuntu

# Clone repository
git clone <your-repo-url>
cd fetchbot-platform

# Create .env file with AWS credentials
nano .env
# (paste configuration from Step 2)

# Start containers
docker-compose -f docker-compose-multi-kali.yml up -d
```

#### Option B: Using User Data Script

Create `ec2-user-data.sh`:

```bash
#!/bin/bash
set -e

# Install Docker
apt-get update
apt-get install -y docker.io docker-compose git awscli

# Start Docker
systemctl start docker
systemctl enable docker

# Clone repository
cd /opt
git clone <your-repo-url> fetchbot
cd fetchbot/fetchbot-platform

# Create .env from parameter store or secrets manager
# (Recommended: store secrets in AWS Secrets Manager)
cat > .env << EOF
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
DATABASE_URL=postgresql://fetchbot:fetchbot123@localhost:5432/fetchbot
REDIS_URL=redis://localhost:6379
AWS_REGION=${AWS::Region}
# ... add other vars ...
EOF

# Start services
docker-compose -f docker-compose-multi-kali.yml up -d

echo "FetchBot.ai deployed successfully"
```

Launch with user data:
```bash
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.medium \
  --key-name fetchbot-key \
  --security-group-ids sg-xxxxx \
  --subnet-id subnet-xxxxx \
  --user-data file://ec2-user-data.sh \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=fetchbot-api-server}]'
```

### Step 4: Configure Load Balancer (Optional)

For production, use an Application Load Balancer:

```bash
# Create target group
aws elbv2 create-target-group \
  --name fetchbot-api-tg \
  --protocol HTTP \
  --port 8000 \
  --vpc-id vpc-xxxxx \
  --health-check-path /health

# Create load balancer
aws elbv2 create-load-balancer \
  --name fetchbot-api-lb \
  --subnets subnet-xxxxx subnet-yyyyy \
  --security-groups sg-xxxxx

# Register EC2 instance with target group
aws elbv2 register-targets \
  --target-group-arn <target-group-arn> \
  --targets Id=<instance-id>
```

### Step 5: Configure RDS Database (Production)

For production, use RDS instead of containerized PostgreSQL:

```bash
# Create RDS instance
aws rds create-db-instance \
  --db-instance-identifier fetchbot-db \
  --db-instance-class db.t3.medium \
  --engine postgres \
  --engine-version 15 \
  --master-username fetchbot \
  --master-user-password <secure-password> \
  --allocated-storage 100 \
  --vpc-security-group-ids sg-xxxxx \
  --db-subnet-group-name <subnet-group-name>

# Update .env with RDS endpoint
DATABASE_URL=postgresql://fetchbot:<password>@fetchbot-db.xxxxx.rds.amazonaws.com:5432/fetchbot
```

### Step 6: Configure ElastiCache for Redis (Production)

```bash
# Create ElastiCache Redis cluster
aws elasticache create-cache-cluster \
  --cache-cluster-id fetchbot-redis \
  --cache-node-type cache.t3.medium \
  --engine redis \
  --num-cache-nodes 1 \
  --security-group-ids sg-xxxxx

# Update .env with ElastiCache endpoint
REDIS_URL=redis://fetchbot-redis.xxxxx.cache.amazonaws.com:6379
```

---

## Architecture Overview

### Local Multi-Kali Setup
```
┌─────────────────────────────────────────────┐
│         Your Local Machine                  │
│                                             │
│  ┌──────────────┐  ┌─────────────────────┐ │
│  │ FetchBot API │  │ Multi-Kali          │ │
│  │ (port 8000)  │─▶│ Orchestrator        │ │
│  └──────────────┘  └─────────────────────┘ │
│         │                    │              │
│         │                    ├─▶ Kali-1 (9001)
│         │                    ├─▶ Kali-2 (9002)
│         │                    └─▶ Kali-3 (9003)
│         │                                   │
│  ┌──────▼─────┐   ┌──────────┐            │
│  │ PostgreSQL │   │  Redis   │            │
│  │ (5432)     │   │  (6379)  │            │
│  └────────────┘   └──────────┘            │
└─────────────────────────────────────────────┘
```

### AWS EC2 Production Setup
```
┌────────────────────────────────────────────────────┐
│                     AWS Cloud                      │
│                                                    │
│  ┌──────────────┐                                 │
│  │  ALB/ELB     │                                 │
│  │  (HTTPS)     │                                 │
│  └──────┬───────┘                                 │
│         │                                          │
│  ┌──────▼───────────────────────────────────────┐ │
│  │        EC2 Instance (API Server)             │ │
│  │                                              │ │
│  │  ┌──────────────┐  ┌─────────────────────┐  │ │
│  │  │ FetchBot API │  │ Multi-Kali          │  │ │
│  │  │ (port 8000)  │─▶│ Orchestrator        │  │ │
│  │  └──────────────┘  └─────────────────────┘  │ │
│  │         │                    │               │ │
│  │         │              ┌─────┴─────┐        │ │
│  │         │              ▼     ▼     ▼        │ │
│  │         │         Kali-1 Kali-2 Kali-3     │ │
│  │         │        (Docker Containers)         │ │
│  └─────────┼──────────────────────────────────┘ │
│            │                                      │
│     ┌──────▼─────┐   ┌────────────┐             │
│     │    RDS     │   │ ElastiCache│             │
│     │ PostgreSQL │   │   Redis    │             │
│     └────────────┘   └────────────┘             │
│                                                  │
│  Per-Organization EC2 Instances (created on-demand)
│  ┌─────────────┐  ┌─────────────┐              │
│  │ Org 1 EC2   │  │ Org 2 EC2   │              │
│  │ + Elastic IP│  │ + Elastic IP│              │
│  └─────────────┘  └─────────────┘              │
└────────────────────────────────────────────────────┘
```

---

## Cost Estimates (AWS)

### Minimal Setup (Development)
- **EC2 t3.medium** (API server): ~$30/month
- **RDS db.t3.micro**: ~$15/month
- **ElastiCache cache.t3.micro**: ~$12/month
- **Data transfer**: ~$5/month
- **Total**: ~$62/month

### Production Setup
- **EC2 t3.large** (API server): ~$60/month
- **RDS db.t3.medium**: ~$60/month
- **ElastiCache cache.t3.medium**: ~$50/month
- **ALB**: ~$20/month
- **Data transfer**: ~$20/month
- **Per-organization EC2**: ~$30/org/month
- **Total**: ~$210/month + $30/org

---

## Security Best Practices

1. **Never commit `.env` file** - it's in `.gitignore`
2. **Use AWS Secrets Manager** for production credentials
3. **Enable VPC Flow Logs** for network monitoring
4. **Use IAM roles** instead of access keys when possible
5. **Rotate API keys regularly**
6. **Enable CloudWatch logs** for monitoring
7. **Use HTTPS** with valid SSL certificate
8. **Restrict security groups** to minimum required access
9. **Enable AWS GuardDuty** for threat detection
10. **Regular security audits** of pentest infrastructure

---

## Monitoring and Logging

### CloudWatch Metrics
```bash
# CPU utilization
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=<instance-id> \
  --start-time 2025-01-01T00:00:00Z \
  --end-time 2025-01-01T23:59:59Z \
  --period 3600 \
  --statistics Average
```

### Application Logs
```bash
# SSH into EC2 instance
ssh -i fetchbot-key.pem ubuntu@<EC2_PUBLIC_IP>

# View container logs
docker logs fetchbot-api -f
docker logs kali-agent-1 -f

# View system logs
sudo journalctl -u docker -f
```

---

## Backup and Disaster Recovery

### Database Backups
```bash
# RDS automated backups (enabled by default)
aws rds modify-db-instance \
  --db-instance-identifier fetchbot-db \
  --backup-retention-period 7

# Manual snapshot
aws rds create-db-snapshot \
  --db-instance-identifier fetchbot-db \
  --db-snapshot-identifier fetchbot-backup-$(date +%Y%m%d)
```

### AMI Snapshots
```bash
# Create AMI of API server
aws ec2 create-image \
  --instance-id <instance-id> \
  --name "fetchbot-api-backup-$(date +%Y%m%d)"
```

---

## Scaling

### Horizontal Scaling (Multiple Kali Agents)

Edit `docker-compose-multi-kali.yml` to add more agents:
```yaml
kali-agent-4:
  build:
    context: ./kali-agent
    dockerfile: Dockerfile
  container_name: kali-agent-4
  environment:
    - AGENT_ID=kali-agent-4
    - AGENT_PORT=9000
  ports:
    - "9004:9000"
  # ... rest of config
```

Update environment variable:
```bash
NUM_KALI_AGENTS=4
```

### Vertical Scaling

Upgrade EC2 instance type:
```bash
# Stop instance
aws ec2 stop-instances --instance-ids <instance-id>

# Change instance type
aws ec2 modify-instance-attribute \
  --instance-id <instance-id> \
  --instance-type t3.large

# Start instance
aws ec2 start-instances --instance-ids <instance-id>
```

---

## Next Steps

1. ✅ Set up local multi-Kali environment
2. ✅ Test API with sample pentest job
3. ⬜ Configure AWS credentials for production
4. ⬜ Deploy to EC2 for production use
5. ⬜ Set up monitoring and alerting
6. ⬜ Configure backup strategy

---

## Support

For issues or questions:
- Check logs: `docker logs fetchbot-api`
- Review documentation: This file
- Open GitHub issue: (your repo)

---

## License

FetchBot.ai - AI-Powered Multi-Tenant Pentest Platform
