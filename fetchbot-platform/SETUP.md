# 🚀 FetchBot.ai Quick Setup Guide

## Step 1: Get Your Anthropic API Key

**This is the ONLY required external credential!**

1. Go to https://console.anthropic.com/
2. Sign up or log in
3. Navigate to "API Keys"
4. Click "Create Key"
5. Copy your API key (starts with `sk-ant-api03-...`)

## Step 2: Configure Environment Variables

The `.env` file has already been created for you at:
```
fetchbot-platform/.env
```

**Edit this file and replace:**
```bash
ANTHROPIC_API_KEY=sk-ant-api03-PASTE_YOUR_KEY_HERE
```

With your actual API key from Step 1.

### That's it! You're ready to go! 🎉

---

## Environment Variables Explained

### ✅ Required (Already Configured for Local Use)

| Variable | Value | Purpose |
|----------|-------|---------|
| `PLATFORM_NAME` | FetchBot.ai | Platform branding |
| `ADMIN_EMAIL` | admin@fetchbot.ai | Admin contact |
| `DATABASE_URL` | postgresql://... | PostgreSQL connection |
| `REDIS_URL` | redis://... | Redis cache connection |
| `JWT_SECRET` | dev_secret... | API authentication |

### 🔑 Required (YOU MUST SET)

| Variable | Example | Purpose |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | sk-ant-api03-... | **Claude AI for orchestration** |

### 🌐 Optional (Only for AWS EC2 Deployment)

| Variable | Purpose | Needed When |
|----------|---------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS authentication | Deploying to EC2 |
| `AWS_SECRET_ACCESS_KEY` | AWS authentication | Deploying to EC2 |
| `AWS_VPC_ID` | VPC for instances | Deploying to EC2 |
| `AWS_SUBNET_ID` | Subnet for instances | Deploying to EC2 |
| `AWS_SECURITY_GROUP_ID` | Security group | Deploying to EC2 |
| `AWS_KEY_PAIR_NAME` | SSH key pair | Deploying to EC2 |
| `AWS_S3_BUCKET` | Evidence storage | Deploying to EC2 |

**Note**: For local Docker testing, AWS variables are **NOT** needed!

---

## Quick Test

After setting your `ANTHROPIC_API_KEY`, test it:

```bash
cd fetchbot-platform

# Build containers
docker-compose build

# Start services
docker-compose up -d

# Check health
curl http://localhost:8000/health

# Check Claude AI orchestrator (should not error)
docker-compose logs api | grep -i claude
```

---

## Troubleshooting

### "ANTHROPIC_API_KEY not set" Error

**Solution**: Edit `.env` file and add your real API key:
```bash
nano fetchbot-platform/.env
# or
vim fetchbot-platform/.env
```

### Invalid API Key Error

**Solution**:
1. Verify your key starts with `sk-ant-api03-`
2. Check for extra spaces or quotes
3. Generate a new key at https://console.anthropic.com/

### AWS Errors (but you don't need AWS)

**Solution**: You can ignore AWS errors if you're only doing local testing. The bots run in Docker containers locally.

---

## Production Deployment Checklist

When deploying to production:

- [ ] Change `JWT_SECRET` to a secure random string
  ```bash
  openssl rand -hex 32
  ```
- [ ] Use a strong `ADMIN_EMAIL`
- [ ] Set up proper AWS credentials (if using EC2)
- [ ] Configure proper database backups
- [ ] Set up SSL/TLS certificates
- [ ] Enable firewall rules
- [ ] Review security settings in `docker-compose.yml`
- [ ] Never commit `.env` to git (already in `.gitignore`)

---

## Getting API Keys

### Anthropic API Key (Required)
- **Website**: https://console.anthropic.com/
- **Pricing**: Pay-as-you-go (includes free credits)
- **Documentation**: https://docs.anthropic.com/

### AWS Credentials (Optional - EC2 only)
- **Website**: https://console.aws.amazon.com/
- **IAM**: Create IAM user with EC2 permissions
- **Documentation**: https://docs.aws.amazon.com/IAM/

---

## Cost Estimate

### Local Docker Testing
- **Cost**: $0 (except Anthropic API usage)
- **Anthropic**: ~$0.01-0.10 per scan depending on findings

### AWS EC2 Deployment (Optional)
- **t3.medium**: ~$0.042/hour (~$30/month if running 24/7)
- **Elastic IP**: $0 while attached, $0.005/hour when not attached
- **Storage**: ~$0.10/GB-month
- **Data Transfer**: First 100GB free/month

### Recommendations
- **Development**: Use local Docker (minimal cost)
- **Production**: Use AWS EC2 for dedicated IPs per organization

---

## Need Help?

- **Documentation**: See `README.md`
- **API Docs**: http://localhost:8000/docs (when running)
- **Issues**: Open a GitHub issue
- **Email**: admin@fetchbot.ai

---

**Ready to scan? Continue with the main README.md for usage instructions!**
