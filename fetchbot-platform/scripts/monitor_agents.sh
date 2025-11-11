#!/bin/bash
# Monitor logs from dynamic Kali agent containers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Monitor logs from dynamic Kali agent containers"
    echo ""
    echo "Options:"
    echo "  -j, --job-id JOB_ID    Monitor containers for specific job ID"
    echo "  -f, --follow           Follow log output (like tail -f)"
    echo "  -n, --tail LINES       Number of lines to show (default: 50)"
    echo "  -l, --list             List all dynamic containers"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --list                           # List all dynamic containers"
    echo "  $0 --job-id abc123                  # Show logs for specific job"
    echo "  $0 --follow                         # Follow logs from all running agents"
    echo "  $0 --job-id abc123 --follow         # Follow logs for specific job"
    exit 1
}

list_containers() {
    echo -e "${BLUE}=== Dynamic Kali Agent Containers ===${NC}\n"

    # Check if any containers exist
    if ! docker ps -a --filter "label=managed_by=fetchbot-dynamic" --format "{{.ID}}" | grep -q .; then
        echo -e "${YELLOW}No dynamic agent containers found${NC}"
        return
    fi

    # Show table of containers
    docker ps -a --filter "label=managed_by=fetchbot-dynamic" \
        --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.CreatedAt}}" | \
        sed "s/^/  /"

    echo ""

    # Count by status
    running=$(docker ps --filter "label=managed_by=fetchbot-dynamic" --format "{{.ID}}" | wc -l | tr -d ' ')
    total=$(docker ps -a --filter "label=managed_by=fetchbot-dynamic" --format "{{.ID}}" | wc -l | tr -d ' ')
    stopped=$((total - running))

    echo -e "  ${GREEN}Running: $running${NC}  ${RED}Stopped: $stopped${NC}  Total: $total"
}

get_containers() {
    local job_id="$1"
    local filter="label=managed_by=fetchbot-dynamic"

    if [ -n "$job_id" ]; then
        filter="$filter,label=job_id=$job_id"
    fi

    docker ps --filter "$filter" --format "{{.Names}}"
}

show_logs() {
    local job_id="$1"
    local follow="$2"
    local tail_lines="${3:-50}"

    containers=$(get_containers "$job_id")

    if [ -z "$containers" ]; then
        if [ -n "$job_id" ]; then
            echo -e "${YELLOW}No running containers found for job: $job_id${NC}"
        else
            echo -e "${YELLOW}No running dynamic agent containers found${NC}"
        fi
        return 1
    fi

    echo -e "${BLUE}=== Monitoring Kali Agent Container Logs ===${NC}\n"

    if [ "$follow" = "true" ]; then
        echo -e "${GREEN}Following logs (Ctrl+C to stop)...${NC}\n"

        # Follow logs from all containers in parallel
        echo "$containers" | while read -r container; do
            (
                echo -e "${YELLOW}[$container]${NC} Starting log stream..."
                docker logs -f --tail "$tail_lines" "$container" 2>&1 | \
                    sed "s/^/[$container] /"
            ) &
        done

        # Wait for all background jobs
        wait
    else
        # Show last N lines from each container
        echo "$containers" | while read -r container; do
            echo -e "${YELLOW}=== Logs from $container ===${NC}"
            docker logs --tail "$tail_lines" "$container" 2>&1
            echo ""
        done
    fi
}

# Parse arguments
JOB_ID=""
FOLLOW="false"
TAIL_LINES=50
ACTION="logs"

while [[ $# -gt 0 ]]; do
    case $1 in
        -j|--job-id)
            JOB_ID="$2"
            shift 2
            ;;
        -f|--follow)
            FOLLOW="true"
            shift
            ;;
        -n|--tail)
            TAIL_LINES="$2"
            shift 2
            ;;
        -l|--list)
            ACTION="list"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Execute action
case $ACTION in
    list)
        list_containers
        ;;
    logs)
        show_logs "$JOB_ID" "$FOLLOW" "$TAIL_LINES"
        ;;
esac
