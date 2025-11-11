#!/bin/bash
# Setup script for dynamic container deployment

set -e

echo "=================================="
echo "Dynamic Container Setup"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi
print_info "Docker is installed ✓"

# Check if Docker is running
if ! docker info &> /dev/null; then
    print_error "Docker daemon is not running. Please start Docker."
    exit 1
fi
print_info "Docker daemon is running ✓"

# Change to script directory
cd "$(dirname "$0")/.."

# Install Python dependencies
print_info "Installing Python dependencies..."
if [ -f requirements.txt ]; then
    pip install -r requirements.txt > /dev/null 2>&1
    print_info "Python dependencies installed ✓"
else
    print_warn "requirements.txt not found, skipping..."
fi

# Create Docker network if it doesn't exist
print_info "Checking Docker network..."
if ! docker network inspect fetchbot_fetchbot &> /dev/null; then
    print_warn "Creating Docker network 'fetchbot_fetchbot'..."
    docker network create fetchbot_fetchbot
    print_info "Docker network created ✓"
else
    print_info "Docker network exists ✓"
fi

# Build Kali agent image
print_info "Building Kali agent Docker image..."
echo "This may take 5-10 minutes on first run..."
if docker build -t fetchbot-kali-agent:latest -f kali-agent/Dockerfile kali-agent/ > /tmp/docker-build.log 2>&1; then
    print_info "Kali agent image built successfully ✓"
else
    print_error "Failed to build Kali agent image. Check /tmp/docker-build.log for details."
    tail -n 20 /tmp/docker-build.log
    exit 1
fi

# Verify image exists
if docker images | grep -q "fetchbot-kali-agent"; then
    IMAGE_SIZE=$(docker images fetchbot-kali-agent:latest --format "{{.Size}}")
    print_info "Image size: $IMAGE_SIZE"
else
    print_error "Image verification failed"
    exit 1
fi

# Test container creation
print_info "Testing container creation..."
TEST_CONTAINER="test-kali-agent-$$"
if docker run --name "$TEST_CONTAINER" \
    -e AGENT_ID="test-agent" \
    -e TARGET_URL="https://example.com" \
    -e JOB_ID="test-job" \
    --network fetchbot_fetchbot \
    -d fetchbot-kali-agent:latest > /dev/null 2>&1; then

    print_info "Waiting for container health check..."
    sleep 5

    # Check if container is running
    if docker ps | grep -q "$TEST_CONTAINER"; then
        print_info "Test container is running ✓"

        # Try to reach health endpoint
        CONTAINER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TEST_CONTAINER")
        if docker exec "$TEST_CONTAINER" curl -s http://localhost:9000/health > /dev/null 2>&1; then
            print_info "Health endpoint accessible ✓"
        else
            print_warn "Health endpoint not ready yet (this is okay)"
        fi
    else
        print_error "Test container failed to start"
        docker logs "$TEST_CONTAINER"
    fi

    # Cleanup test container
    print_info "Cleaning up test container..."
    docker stop "$TEST_CONTAINER" > /dev/null 2>&1
    docker rm "$TEST_CONTAINER" > /dev/null 2>&1
    print_info "Test container cleaned up ✓"
else
    print_error "Failed to create test container"
    exit 1
fi

echo ""
echo "=================================="
echo -e "${GREEN}Setup Complete!${NC}"
echo "=================================="
echo ""
echo "Next steps:"
echo "1. Start the API server:"
echo "   $ python main.py"
echo ""
echo "2. Run a scan with dynamic containers:"
echo "   $ curl -X POST http://localhost:8000/scan \\"
echo "     -H \"Authorization: Bearer YOUR_TOKEN\" \\"
echo "     -H \"Content-Type: application/json\" \\"
echo "     -d '{\"target\": \"https://example.com\"}'"
echo ""
echo "3. Monitor dynamic containers:"
echo "   $ docker ps --filter \"label=managed_by=fetchbot-dynamic\""
echo ""
echo "See DYNAMIC_CONTAINERS_SETUP.md for detailed documentation."
echo ""
