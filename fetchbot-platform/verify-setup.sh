#!/bin/bash

# FetchBot Dynamic Agent System - Pre-flight Verification
# Run this before starting Docker containers

echo "🔍 FetchBot Dynamic Agent System - Setup Verification"
echo "======================================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

# Function to check file exists
check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✅${NC} $2"
        return 0
    else
        echo -e "${RED}❌${NC} $2 - NOT FOUND: $1"
        ERRORS=$((ERRORS + 1))
        return 1
    fi
}

# Function to check directory exists
check_dir() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✅${NC} $2"
        return 0
    else
        echo -e "${RED}❌${NC} $2 - NOT FOUND: $1"
        ERRORS=$((ERRORS + 1))
        return 1
    fi
}

# Function to check file contains text
check_contains() {
    if grep -q "$2" "$1" 2>/dev/null; then
        echo -e "${GREEN}✅${NC} $3"
        return 0
    else
        echo -e "${RED}❌${NC} $3"
        ERRORS=$((ERRORS + 1))
        return 1
    fi
}

echo -e "${BLUE}[1/8] Checking Core Infrastructure${NC}"
check_dir "core" "Core module directory"
check_dir "core/agents" "Agents directory"
check_dir "core/tools" "Tools directory"
check_dir "core/llm" "LLM integration directory"
check_dir "core/prompts" "Prompts directory"
echo ""

echo -e "${BLUE}[2/8] Checking Agent System Files${NC}"
check_file "core/agents/base_agent.py" "Base agent class"
check_file "core/agents/root_agent.py" "Root coordinator agent"
check_file "core/agents/state.py" "Agent state management"
check_file "core/agents/agent_graph.py" "Agent graph coordination"
echo ""

echo -e "${BLUE}[3/8] Checking Tool System Files${NC}"
check_file "core/tools/registry.py" "Tool registry"
check_file "core/tools/executor.py" "Tool executor"
check_file "core/tools/coordination_tools.py" "Coordination tools (create_agent, etc.)"
check_file "core/tools/network_tools.py" "Network scanning tools"
check_file "core/tools/web_tools.py" "Web scanning tools"
check_file "core/tools/database_tools.py" "Database testing tools"
check_file "core/tools/api_tools.py" "API security testing tools"
echo ""

echo -e "${BLUE}[4/8] Checking Prompt Module Templates${NC}"
check_file "core/prompts/base_system_prompt.jinja" "Base system prompt"
check_file "core/prompts/vulnerabilities/sql_injection.jinja" "SQL injection expertise module"
check_file "core/prompts/vulnerabilities/xss.jinja" "XSS expertise module"
check_file "core/prompts/vulnerabilities/api_testing.jinja" "API testing expertise module"
check_file "core/prompts/vulnerabilities/authentication.jinja" "Authentication expertise module"
echo ""

echo -e "${BLUE}[5/8] Checking LLM Integration${NC}"
check_file "core/llm/llm.py" "LLM client wrapper"
check_file "core/llm/config.py" "LLM configuration"
check_file "core/llm/parsers.py" "Tool invocation parsers"
echo ""

echo -e "${BLUE}[6/8] Checking Orchestrator${NC}"
check_file "core/orchestrator.py" "Dynamic orchestrator"
echo ""

echo -e "${BLUE}[7/8] Checking Configuration${NC}"
check_file "config.py" "Configuration file"
check_contains "config.py" "use_dynamic_agents" "config.py contains use_dynamic_agents field"
check_file "requirements.txt" "Python dependencies"
check_contains "requirements.txt" "jinja2" "requirements.txt contains jinja2"
check_contains "requirements.txt" "email-validator" "requirements.txt contains email-validator"
echo ""

echo -e "${BLUE}[8/8] Checking Environment Setup${NC}"
if [ -f ".env" ]; then
    echo -e "${GREEN}✅${NC} .env file exists"

    if grep -q "USE_DYNAMIC_AGENTS=true" .env; then
        echo -e "${GREEN}✅${NC} Dynamic agents enabled in .env"
    else
        echo -e "${YELLOW}⚠️${NC}  USE_DYNAMIC_AGENTS not set to true in .env"
        WARNINGS=$((WARNINGS + 1))
    fi

    if grep -q "ANTHROPIC_API_KEY=" .env && ! grep -q "ANTHROPIC_API_KEY=sk-ant-api03-your-actual-key-here" .env; then
        echo -e "${GREEN}✅${NC} ANTHROPIC_API_KEY appears to be set"
    else
        echo -e "${YELLOW}⚠️${NC}  ANTHROPIC_API_KEY needs to be set with real key"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${RED}❌${NC} .env file not found"
    echo -e "${YELLOW}📝${NC}  Create .env file with:"
    echo "      DATABASE_URL=postgresql://fetchbot:fetchbot123@postgres:5432/fetchbot"
    echo "      REDIS_URL=redis://redis:6379/0"
    echo "      ANTHROPIC_API_KEY=your-actual-key-here"
    echo "      SECRET_KEY=change-this-in-production"
    echo "      USE_DYNAMIC_AGENTS=true"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# Count files
TOTAL_PY_FILES=$(find core -name "*.py" | wc -l)
TOTAL_JINJA_FILES=$(find core/prompts -name "*.jinja" | wc -l)

echo "======================================================"
echo -e "${BLUE}Summary:${NC}"
echo "  Core Python files: $TOTAL_PY_FILES"
echo "  Prompt templates: $TOTAL_JINJA_FILES"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✅ All checks passed! System is ready.${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo "  1. docker-compose build api --no-cache"
    echo "  2. docker-compose up -d"
    echo "  3. docker-compose logs -f api"
    echo ""
    echo "See COMPLETE_SETUP_GUIDE.md for detailed instructions."
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠️  $WARNINGS warning(s) - review above${NC}"
    echo ""
    echo -e "${BLUE}You can proceed, but address warnings:${NC}"
    echo "  1. Ensure .env has USE_DYNAMIC_AGENTS=true"
    echo "  2. Set real ANTHROPIC_API_KEY in .env"
    echo "  3. docker-compose build api --no-cache"
    echo "  4. docker-compose up -d"
    exit 0
else
    echo -e "${RED}❌ $ERRORS error(s) found - fix before proceeding${NC}"
    if [ $WARNINGS -gt 0 ]; then
        echo -e "${YELLOW}⚠️  $WARNINGS warning(s) also present${NC}"
    fi
    echo ""
    echo "Review errors above and ensure all files exist."
    exit 1
fi
