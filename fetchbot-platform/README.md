# FetchBot.ai - AI-Powered Multi-Tenant Pentest Platform

Each organization gets dedicated AWS EC2 instance with Elastic IP for isolated pentesting.

## Quick Start

1. **Configure AWS credentials in `.env`:**
```bash
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
ANTHROPIC_API_KEY=your_key
```

2. **Start platform:**
```bash
docker-compose up -d
```

3. **Create organization:**
```bash
./scripts/create-org.sh "Acme Corp" admin@acme.com example.com
```

4. **Start pentest:**
```bash
curl -X POST http://localhost:8000/api/pentest \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Security Audit",
    "target": "example.com"
  }'
```

## API Documentation

Visit http://localhost:8000/docs

## Architecture

- Each org gets dedicated EC2 instance
- Dedicated Elastic IP for attacks
- Three specialized bots: UI, Network, DB
- AI-powered orchestration with Claude

## Support

Email: admin@fetchbot.ai
