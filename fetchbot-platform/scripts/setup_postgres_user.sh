#!/bin/bash
# Setup fetchbot PostgreSQL user for local development

set -e

echo "=================================="
echo "PostgreSQL User Setup"
echo "=================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if psql is available
if ! command -v psql &> /dev/null; then
    print_error "psql command not found. Please install PostgreSQL first."
    exit 1
fi

print_info "Setting up fetchbot database user..."

# Create user and database
psql postgres <<EOF
-- Drop existing user and database if they exist (for clean setup)
DROP DATABASE IF EXISTS fetchbot;
DROP USER IF EXISTS fetchbot;

-- Create new user
CREATE USER fetchbot WITH PASSWORD 'fetchbot123';

-- Create database
CREATE DATABASE fetchbot OWNER fetchbot;

-- Grant all privileges
GRANT ALL PRIVILEGES ON DATABASE fetchbot TO fetchbot;

-- Connect to fetchbot database and grant schema privileges
\c fetchbot
GRANT ALL ON SCHEMA public TO fetchbot;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO fetchbot;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO fetchbot;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO fetchbot;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO fetchbot;

-- Verify user was created
\du fetchbot
EOF

if [ $? -eq 0 ]; then
    print_info "✅ Database user 'fetchbot' created successfully!"
    print_info "✅ Database 'fetchbot' created successfully!"
    echo ""
    echo "You can now run:"
    echo "  python main.py"
    echo ""
else
    print_error "❌ Failed to create database user"
    exit 1
fi
