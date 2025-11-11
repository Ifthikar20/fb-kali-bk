#!/bin/bash
# Complete Setup and Run Script for FetchBot Dynamic Containers

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

print_info() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check if running in correct directory
if [ ! -f "docker-compose-multi-kali.yml" ]; then
    print_error "Please run this script from the fetchbot-platform directory"
    exit 1
fi

print_header "FetchBot.ai - Complete Setup"

# Step 1: Stop conflicting services
print_header "Step 1: Stop Conflicting PostgreSQL"

if command -v brew &> /dev/null; then
    if brew services list | grep -q "postgresql.*started"; then
        print_warn "Stopping Homebrew PostgreSQL to avoid port conflicts..."
        brew services stop postgresql@14 2>/dev/null || brew services stop postgresql 2>/dev/null || true
        print_info "Homebrew PostgreSQL stopped"
    else
        print_info "No conflicting Homebrew PostgreSQL running"
    fi
fi

# Step 2: Start Docker containers
print_header "Step 2: Start Docker Infrastructure"

print_info "Stopping any existing containers..."
docker-compose -f docker-compose-multi-kali.yml down 2>/dev/null || true

print_info "Starting PostgreSQL and Redis..."
docker-compose -f docker-compose-multi-kali.yml up -d postgres redis

print_info "Waiting for PostgreSQL to be ready..."
sleep 10

# Wait for PostgreSQL to be healthy
for i in {1..30}; do
    if docker exec fetchbot-postgres pg_isready -U fetchbot &>/dev/null; then
        print_info "PostgreSQL is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "PostgreSQL failed to start"
        exit 1
    fi
    sleep 1
done

# Step 3: Check .env file
print_header "Step 3: Check Configuration"

if [ ! -f ".env" ]; then
    print_warn "No .env file found, creating from example..."
    cp .env.example .env
    print_warn "Please edit .env and add your ANTHROPIC_API_KEY"
    print_warn "Then run this script again"
    exit 0
fi

# Verify DATABASE_URL uses localhost
if grep -q "DATABASE_URL.*@postgres:" .env; then
    print_warn "Fixing DATABASE_URL in .env to use localhost..."
    sed -i.bak 's/@postgres:/@localhost:/g' .env
    print_info "DATABASE_URL updated to use localhost"
fi

if grep -q "REDIS_URL.*redis://redis:" .env; then
    print_warn "Fixing REDIS_URL in .env to use localhost..."
    sed -i.bak 's/redis:\/\/redis:/redis:\/\/localhost:/g' .env
    print_info "REDIS_URL updated to use localhost"
fi

# Check for API key
if grep -q "your_anthropic_api_key_here" .env; then
    print_error "Please set ANTHROPIC_API_KEY in .env file"
    echo "Get your API key from: https://console.anthropic.com/"
    exit 1
fi

print_info "Configuration looks good"

# Step 4: Activate virtual environment
print_header "Step 4: Setup Python Environment"

if [ ! -d "venv" ]; then
    print_info "Creating virtual environment..."
    python3 -m venv venv
fi

print_info "Activating virtual environment..."
source venv/bin/activate

print_info "Installing/updating dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

print_info "Python environment ready"

# Step 5: Create database tables and admin user
print_header "Step 5: Initialize Database"

print_info "Creating database tables..."
python -c "from models import init_db; init_db()" || print_error "Failed to create tables"

print_info "Checking for admin user..."
if python scripts/create_admin_user.py 2>&1 | grep -q "UNIQUE constraint"; then
    print_warn "Admin user already exists, skipping creation"
else
    print_info "Admin user created successfully"
fi

# Step 6: Build Kali agent image (optional, for dynamic containers)
print_header "Step 6: Build Kali Agent Image (Optional)"

if docker images | grep -q "fetchbot-kali-agent"; then
    print_info "Kali agent image already exists"
else
    print_warn "Kali agent image not found"
    echo "To use dynamic containers, build the image with:"
    echo "  docker build -t fetchbot-kali-agent:latest -f kali-agent/Dockerfile kali-agent/"
fi

# Step 7: Display summary
print_header "Setup Complete!"

echo ""
echo -e "${GREEN}✓ PostgreSQL running on localhost:5432${NC}"
echo -e "${GREEN}✓ Redis running on localhost:6379${NC}"
echo -e "${GREEN}✓ Database initialized${NC}"
echo -e "${GREEN}✓ Admin user ready${NC}"
echo ""

# Check if dynamic agents are enabled
if grep -q "USE_DYNAMIC_AGENTS=true" .env; then
    echo -e "${BLUE}Dynamic Container Mode: ENABLED${NC}"
    echo ""
    if docker images | grep -q "fetchbot-kali-agent"; then
        echo -e "${GREEN}✓ Kali agent image built${NC}"
    else
        echo -e "${YELLOW}! Kali agent image not built${NC}"
        echo "  Build with: docker build -t fetchbot-kali-agent:latest -f kali-agent/Dockerfile kali-agent/"
    fi
else
    echo -e "${YELLOW}Dynamic Container Mode: DISABLED${NC}"
    echo "Enable by setting USE_DYNAMIC_AGENTS=true in .env"
fi

echo ""
print_header "How to Run"

echo "1. Start the API server:"
echo "   ${GREEN}source venv/bin/activate${NC}"
echo "   ${GREEN}python main.py${NC}"
echo ""
echo "2. Access the platform at:"
echo "   ${GREEN}http://localhost:8000${NC}"
echo ""
echo "3. Login credentials:"
echo "   Username: ${GREEN}admin${NC}"
echo "   Password: ${GREEN}admin123${NC}"
echo ""
echo "4. To test dynamic containers:"
echo "   - Navigate to the scans page"
echo "   - Create a new scan with target: https://example.com"
echo "   - Watch containers spawn dynamically!"
echo ""
echo "5. Monitor dynamic containers:"
echo "   ${GREEN}docker ps --filter \"label=managed_by=fetchbot-dynamic\"${NC}"
echo ""

print_header "Troubleshooting"

echo "View logs:"
echo "  ${GREEN}docker-compose -f docker-compose-multi-kali.yml logs -f postgres${NC}"
echo ""
echo "Reset database:"
echo "  ${GREEN}docker-compose -f docker-compose-multi-kali.yml down -v${NC}"
echo "  ${GREEN}./scripts/setup_and_run.sh${NC}"
echo ""
echo "Stop all services:"
echo "  ${GREEN}docker-compose -f docker-compose-multi-kali.yml down${NC}"
echo ""
