#!/bin/bash
# FetchBot.ai - EC2 Kali Linux Deployment Script
# This script deploys a Kali Linux EC2 instance with Docker containers

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║                                                          ║"
echo "║          FetchBot.ai - EC2 Kali Deployment              ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found"
    echo "Please create .env file with AWS credentials"
    exit 1
fi

# Load environment variables
source .env

# Validate AWS credentials
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ "$AWS_ACCESS_KEY_ID" = "YOUR_AWS_ACCESS_KEY" ]; then
    echo "❌ Error: AWS_ACCESS_KEY_ID not set in .env"
    exit 1
fi

if [ -z "$AWS_SECRET_ACCESS_KEY" ] || [ "$AWS_SECRET_ACCESS_KEY" = "YOUR_AWS_SECRET_KEY" ]; then
    echo "❌ Error: AWS_SECRET_ACCESS_KEY not set in .env"
    exit 1
fi

echo "✓ AWS credentials found"
echo ""

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo "⚠️  AWS CLI not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y awscli
fi

echo "Step 1: Creating Security Group..."
SECURITY_GROUP_NAME="fetchbot-kali-sg"
DESCRIPTION="FetchBot.ai Kali Linux security group"

# Create security group if not exists
SG_ID=$(aws ec2 describe-security-groups \
    --region $AWS_REGION \
    --filters "Name=group-name,Values=$SECURITY_GROUP_NAME" \
    --query 'SecurityGroups[0].GroupId' \
    --output text 2>/dev/null || echo "None")

if [ "$SG_ID" = "None" ] || [ -z "$SG_ID" ]; then
    echo "Creating new security group..."
    SG_ID=$(aws ec2 create-security-group \
        --region $AWS_REGION \
        --group-name $SECURITY_GROUP_NAME \
        --description "$DESCRIPTION" \
        --query 'GroupId' \
        --output text)

    # Add SSH rule
    aws ec2 authorize-security-group-ingress \
        --region $AWS_REGION \
        --group-id $SG_ID \
        --protocol tcp \
        --port 22 \
        --cidr 0.0.0.0/0

    # Add Docker API ports (9001-9003 for Kali agents)
    aws ec2 authorize-security-group-ingress \
        --region $AWS_REGION \
        --group-id $SG_ID \
        --protocol tcp \
        --port 9001-9003 \
        --cidr 0.0.0.0/0

    # Add main API port (8000)
    aws ec2 authorize-security-group-ingress \
        --region $AWS_REGION \
        --group-id $SG_ID \
        --protocol tcp \
        --port 8000 \
        --cidr 0.0.0.0/0

    echo "✓ Security group created: $SG_ID"
else
    echo "✓ Using existing security group: $SG_ID"
fi

echo ""
echo "Step 2: Creating User Data Script..."

# Create user data script for EC2 instance
cat > /tmp/ec2-user-data.sh << 'EOF'
#!/bin/bash
set -e

echo "=== FetchBot.ai Kali Linux EC2 Setup ==="

# Update system
apt-get update
apt-get upgrade -y

# Install Docker
apt-get install -y docker.io docker-compose git

# Start Docker
systemctl start docker
systemctl enable docker

# Create FetchBot directory
mkdir -p /opt/fetchbot
cd /opt/fetchbot

# Clone the repository (or you can copy files)
# git clone <your-repo-url> .

# Pull Kali Linux Docker image
docker pull kalilinux/kali-rolling:latest

# Create docker-compose.yml for 3 Kali agents
cat > docker-compose.yml << 'COMPOSE'
version: '3.8'

services:
  kali-agent-1:
    image: kalilinux/kali-rolling:latest
    container_name: kali-agent-1
    ports:
      - "9001:9000"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    command: tail -f /dev/null
    restart: unless-stopped

  kali-agent-2:
    image: kalilinux/kali-rolling:latest
    container_name: kali-agent-2
    ports:
      - "9002:9000"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    command: tail -f /dev/null
    restart: unless-stopped

  kali-agent-3:
    image: kalilinux/kali-rolling:latest
    container_name: kali-agent-3
    ports:
      - "9003:9000"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    command: tail -f /dev/null
    restart: unless-stopped
COMPOSE

# Start containers
docker-compose up -d

# Install security tools in each container
for i in 1 2 3; do
    echo "Installing tools in kali-agent-$i..."
    docker exec kali-agent-$i bash -c "
        apt-get update && apt-get install -y \
            nmap masscan nikto sqlmap dirb whatweb \
            python3 python3-pip curl wget netcat-traditional \
            dnsutils net-tools iputils-ping
    "
done

echo "=== Setup Complete ==="
echo "Kali agents are running on ports 9001, 9002, 9003"
EOF

echo "✓ User data script created"
echo ""

echo "Step 3: Launching EC2 Instance..."

# Get latest Ubuntu AMI (we'll install Kali tools on it)
AMI_ID=$(aws ec2 describe-images \
    --region $AWS_REGION \
    --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
              "Name=state,Values=available" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
    --output text)

echo "Using AMI: $AMI_ID"

# Launch instance
INSTANCE_ID=$(aws ec2 run-instances \
    --region $AWS_REGION \
    --image-id $AMI_ID \
    --instance-type t3.medium \
    --key-name ${AWS_KEY_PAIR_NAME:-fetchbot-key} \
    --security-group-ids $SG_ID \
    --user-data file:///tmp/ec2-user-data.sh \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=fetchbot-kali-instance},{Key=Platform,Value=FetchBot.ai}]" \
    --query 'Instances[0].InstanceId' \
    --output text)

echo "✓ Instance launched: $INSTANCE_ID"
echo ""

echo "Step 4: Waiting for instance to start..."
aws ec2 wait instance-running --region $AWS_REGION --instance-ids $INSTANCE_ID

echo "✓ Instance is running"
echo ""

echo "Step 5: Getting instance details..."
INSTANCE_INFO=$(aws ec2 describe-instances \
    --region $AWS_REGION \
    --instance-ids $INSTANCE_ID \
    --query 'Reservations[0].Instances[0].[PublicIpAddress,PublicDnsName]' \
    --output text)

PUBLIC_IP=$(echo $INSTANCE_INFO | awk '{print $1}')
PUBLIC_DNS=$(echo $INSTANCE_INFO | awk '{print $2}')

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                  DEPLOYMENT SUCCESSFUL                   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Instance ID:  $INSTANCE_ID"
echo "Public IP:    $PUBLIC_IP"
echo "Public DNS:   $PUBLIC_DNS"
echo ""
echo "Kali Agents will be available on:"
echo "  - http://$PUBLIC_IP:9001  (Kali Agent 1)"
echo "  - http://$PUBLIC_IP:9002  (Kali Agent 2)"
echo "  - http://$PUBLIC_IP:9003  (Kali Agent 3)"
echo ""
echo "SSH Access:"
echo "  ssh ubuntu@$PUBLIC_IP"
echo ""
echo "Note: Please wait 5-10 minutes for Docker setup to complete"
echo "Check status: ssh ubuntu@$PUBLIC_IP 'sudo docker ps'"
echo ""

# Save instance info
cat > ec2-instance-info.txt << EOF
FetchBot.ai EC2 Kali Instance
==============================
Instance ID: $INSTANCE_ID
Public IP: $PUBLIC_IP
Public DNS: $PUBLIC_DNS
Security Group: $SG_ID
Region: $AWS_REGION

Kali Agent Endpoints:
- http://$PUBLIC_IP:9001
- http://$PUBLIC_IP:9002
- http://$PUBLIC_IP:9003

Created: $(date)
EOF

echo "✓ Instance details saved to ec2-instance-info.txt"
echo ""
echo "To terminate this instance:"
echo "  aws ec2 terminate-instances --region $AWS_REGION --instance-ids $INSTANCE_ID"
