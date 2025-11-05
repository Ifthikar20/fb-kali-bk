#!/bin/bash
# FetchBot.ai - Local Multi-Kali Quick Start Script
# Starts 3 Kali Linux containers locally for testing

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║                                                          ║"
echo "║         FetchBot.ai - Local Multi-Kali Setup            ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check if Docker is running
if ! docker ps &> /dev/null; then
    echo "❌ Error: Docker is not running"
    echo "Please start Docker and try again"
    exit 1
fi

echo "✓ Docker is running"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  Warning: .env file not found"
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo ""
    echo "⚠️  IMPORTANT: Please edit .env and set your ANTHROPIC_API_KEY"
    echo "Run: nano .env"
    exit 1
fi

# Check if ANTHROPIC_API_KEY is set
if grep -q "your_anthropic_api_key_here" .env; then
    echo "❌ Error: ANTHROPIC_API_KEY not configured in .env"
    echo "Please edit .env and set your Anthropic API key"
    echo "Run: nano .env"
    exit 1
fi

echo "✓ Configuration found"
echo ""

# Check if containers are already running
if docker ps | grep -q "kali-agent"; then
    echo "⚠️  Kali agents are already running"
    read -p "Do you want to restart them? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Stopping existing containers..."
        docker compose -f docker-compose-multi-kali.yml down
    else
        echo "Exiting..."
        exit 0
    fi
fi

echo "Step 1/4: Building containers (this may take 10-15 minutes first time)..."
docker compose -f docker-compose-multi-kali.yml build

echo ""
echo "Step 2/4: Starting all services..."
docker compose -f docker-compose-multi-kali.yml up -d

echo ""
echo "Step 3/4: Waiting for services to be ready..."
sleep 10

echo ""
echo "Step 4/4: Verifying services..."

# Check API
echo -n "  API Server (port 8000)... "
if curl -s http://localhost:8000/health > /dev/null; then
    echo "✓"
else
    echo "⚠️  (may still be starting)"
fi

# Check Kali Agents
for i in 1 2 3; do
    port=$((9000 + i))
    echo -n "  Kali Agent $i (port $port)... "
    if curl -s http://localhost:$port/health > /dev/null; then
        echo "✓"
    else
        echo "⚠️  (may still be starting)"
    fi
done

# Check PostgreSQL
echo -n "  PostgreSQL... "
if docker exec fetchbot-postgres pg_isready -U fetchbot &> /dev/null; then
    echo "✓"
else
    echo "⚠️"
fi

# Check Redis
echo -n "  Redis... "
if docker exec fetchbot-redis redis-cli ping &> /dev/null; then
    echo "✓"
else
    echo "⚠️"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                    SETUP COMPLETE                        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Services running:"
echo "  🌐 API Server:     http://localhost:8000"
echo "  📚 API Docs:       http://localhost:8000/docs"
echo "  🔧 Kali Agent 1:   http://localhost:9001"
echo "  🔧 Kali Agent 2:   http://localhost:9002"
echo "  🔧 Kali Agent 3:   http://localhost:9003"
echo ""
echo "Quick Tests:"
echo ""
echo "  # Health check"
echo "  curl http://localhost:8000/health"
echo ""
echo "  # Test Kali agent"
echo "  curl http://localhost:9001/health"
echo ""
echo "  # View logs"
echo "  docker compose -f docker-compose-multi-kali.yml logs -f"
echo ""
echo "  # Stop services"
echo "  docker compose -f docker-compose-multi-kali.yml down"
echo ""
echo "For full documentation, see DEPLOYMENT_GUIDE.md"
echo ""
