#!/bin/bash

# FetchBot - Create .env file helper script

echo "🔧 FetchBot - Environment File Setup"
echo "====================================="
echo ""

if [ -f ".env" ]; then
    echo "⚠️  .env file already exists!"
    echo ""
    read -p "Overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted. Keeping existing .env file."
        exit 0
    fi
fi

echo "Creating .env file..."

cat > .env << 'EOF'
# Database Configuration
DATABASE_URL=postgresql://fetchbot:fetchbot123@postgres:5432/fetchbot

# Redis Configuration
REDIS_URL=redis://redis:6379/0

# AI Configuration - REQUIRED!
# Get your API key from: https://console.anthropic.com/
ANTHROPIC_API_KEY=sk-ant-api03-your-actual-key-here

# Security
SECRET_KEY=change-this-to-random-string-in-production

# ⭐ ENABLE DYNAMIC MULTI-AGENT SYSTEM ⭐
USE_DYNAMIC_AGENTS=true

# AWS Configuration (OPTIONAL - only for EC2 deployment)
# You can safely leave these commented out for local Docker setup
# AWS_REGION=us-east-1
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=
# AWS_VPC_ID=
# AWS_SUBNET_ID=
# AWS_SECURITY_GROUP_ID=
# AWS_KEY_PAIR_NAME=
# AWS_S3_BUCKET=
EOF

echo ""
echo "✅ .env file created successfully!"
echo ""
echo "⚠️  IMPORTANT: Edit .env and add your ANTHROPIC_API_KEY"
echo ""
echo "  1. Get API key from: https://console.anthropic.com/"
echo "  2. Edit .env:  nano .env"
echo "  3. Replace: sk-ant-api03-your-actual-key-here"
echo "  4. Save and exit (Ctrl+X, then Y, then Enter)"
echo ""
echo "Current .env file contents:"
echo "====================================="
cat .env
echo "====================================="
echo ""
echo "After adding your API key, run:"
echo "  ./verify-setup.sh"
