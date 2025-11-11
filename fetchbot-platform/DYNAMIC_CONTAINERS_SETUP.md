# Dynamic Container Deployment Setup

This document explains the new dynamic container deployment system that spawns fresh Kali agent containers for each scan, eliminating state pollution between scans.

## Overview

### Problem Solved
Previously, the AgentGraph singleton persisted across scans, causing old target URLs to be read when running new scans. This led to confusion where scanning a new domain would still reference the old domain.

### Solution
The system now:
1. **Spawns fresh containers** for each scan with the target URL as an environment variable
2. **Clears the AgentGraph** before each scan to prevent state pollution
3. **Distributes work** across multiple Kali agents using round-robin load balancing
4. **Cleans up containers** automatically after scan completion or failure

## Architecture Changes

### 1. Container Manager (`core/utils/container_manager.py`)
New module that manages dynamic container lifecycle:
- `spawn_kali_agents()` - Creates fresh containers with target URL and job ID
- `cleanup_job_containers()` - Removes containers after scan completion
- `_wait_for_agents_health()` - Ensures containers are ready before use

### 2. Orchestrator (`core/orchestrator.py`)
Updated to use dynamic containers:
- Clears AgentGraph at scan start (line 75-77)
- Spawns dynamic containers if enabled (line 89-109)
- Passes sandbox URLs to RootAgent (line 120-125)
- Cleans up containers in finally block (line 186-194)

### 3. RootAgent (`core/agents/root_agent.py`)
Now accepts multiple sandbox URLs:
- `sandbox_urls` parameter for load distribution
- Stores all URLs and distributes to child agents

### 4. AgentState (`core/agents/state.py`)
Supports multiple sandbox URLs:
- `sandbox_urls` parameter stores all available agent URLs
- Enables child agents to distribute work

### 5. Coordination Tools (`core/tools/coordination_tools.py`)
Round-robin distribution of sandbox URLs:
- Selects sandbox URL based on agent count (line 62-65)
- Distributes load evenly across Kali agents

### 6. Kali Agent (`kali-agent/dynamic_kali_agent.py`)
Reads configuration from environment:
- `TARGET_URL` - Default target for this agent
- `JOB_ID` - Job identifier
- Logs configuration on startup

## Setup Instructions

### Prerequisites
- Docker installed and running
- Docker network `fetchbot_fetchbot` exists (created by docker-compose)
- Python dependencies installed (see requirements.txt)

### 1. Install Python Dependencies
```bash
cd fetchbot-platform
pip install -r requirements.txt
```

The key new dependency is:
- `docker==7.0.0` - Python Docker SDK for container management

### 2. Build Kali Agent Image
The Kali agent image must be built with the correct tag:

```bash
cd fetchbot-platform
docker build -t fetchbot-kali-agent:latest -f kali-agent/Dockerfile kali-agent/
```

This creates the `fetchbot-kali-agent:latest` image that the container manager expects.

### 3. Verify Docker Network
Ensure the Docker network exists:

```bash
docker network ls | grep fetchbot
```

If not found, create it:
```bash
docker network create fetchbot_fetchbot
```

Or use docker-compose:
```bash
docker-compose -f docker-compose-multi-kali.yml up -d postgres redis
```

## Usage

### Starting a Scan with Dynamic Containers

#### API Request
```bash
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com"
  }'
```

#### What Happens
1. **AgentGraph cleared** - Previous scan state removed
2. **Containers spawned** - 3 fresh Kali agents created:
   - `kali-agent-{job_id}-1` on port 9100
   - `kali-agent-{job_id}-2` on port 9101
   - `kali-agent-{job_id}-3` on port 9102
3. **Environment variables set**:
   ```
   AGENT_ID=kali-agent-{job_id}-1
   TARGET_URL=https://example.com
   JOB_ID={job_id}
   ```
4. **Health checks** - Wait up to 120s for containers to become healthy
5. **Scan execution** - RootAgent coordinates the assessment
6. **Cleanup** - Containers stopped and removed automatically

### Monitoring Dynamic Containers

#### Check Running Containers
```bash
docker ps --filter "label=managed_by=fetchbot-dynamic"
```

#### Check Containers for Specific Job
```bash
docker ps --filter "label=job_id=YOUR_JOB_ID"
```

#### View Container Logs
```bash
docker logs kali-agent-{job_id}-1
```

### Configuration Options

The orchestrator's `run_scan()` method accepts these parameters:

```python
await orchestrator.run_scan(
    target="https://example.com",
    job_id="unique-job-id",
    db_url="postgresql://...",
    use_dynamic_containers=True,  # Enable dynamic containers (default: True)
    num_agents=3                  # Number of agents to spawn (default: 3)
)
```

#### Disable Dynamic Containers (Use Static Agents)
Set `use_dynamic_containers=False` to use the old behavior with static containers:
- `http://kali-agent-1:9000`
- `http://kali-agent-2:9000`
- `http://kali-agent-3:9000`

These must be running via docker-compose:
```bash
docker-compose -f docker-compose-multi-kali.yml up -d
```

## Troubleshooting

### Issue: "Kali agent image not found"
**Solution:** Build the image:
```bash
docker build -t fetchbot-kali-agent:latest -f kali-agent/Dockerfile kali-agent/
```

### Issue: "Timeout waiting for agents to become healthy"
**Possible causes:**
1. Image build failed or is incomplete
2. Network connectivity issues
3. Insufficient system resources

**Solution:**
```bash
# Check container status
docker ps -a --filter "label=managed_by=fetchbot-dynamic"

# Check container logs
docker logs kali-agent-{job_id}-1

# Verify image exists
docker images | grep fetchbot-kali-agent
```

### Issue: Containers not cleaning up
**Solution:** Manual cleanup:
```bash
# Stop all dynamic containers
docker stop $(docker ps -q --filter "label=managed_by=fetchbot-dynamic")

# Remove all dynamic containers
docker rm $(docker ps -aq --filter "label=managed_by=fetchbot-dynamic")
```

### Issue: "Cannot connect to Docker daemon"
**Solution:** Ensure Docker is running and the API user has permissions:
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER

# Restart Docker service
sudo systemctl restart docker
```

## Performance Considerations

### Container Startup Time
- Building containers: ~60-90 seconds (first time only)
- Starting containers: ~30-45 seconds
- Health check wait: Up to 120 seconds (typically 10-20s)

**Total scan overhead:** ~40-60 seconds per scan

### Resource Usage
Each Kali agent container requires:
- **Memory:** ~500MB-1GB
- **CPU:** 1-2 cores during active scanning
- **Disk:** ~2GB for image (shared across containers)

**Recommended:** 8GB RAM, 4+ CPU cores for 3 agents

### Scaling
Adjust `num_agents` based on your system:
- **Light scans:** 1-2 agents
- **Standard scans:** 3 agents (default)
- **Heavy scans:** 5+ agents (requires more resources)

## Benefits

### Isolation
- ✅ Each scan gets fresh containers
- ✅ No state pollution between scans
- ✅ Target URL guaranteed correct per scan

### Security
- ✅ Containers run with limited permissions (NET_ADMIN, NET_RAW only)
- ✅ Automatic cleanup prevents resource leaks
- ✅ Job-specific labeling for audit trails

### Flexibility
- ✅ Dynamic scaling based on workload
- ✅ Easy to test different agent counts
- ✅ Can mix static and dynamic deployments

## Migration from Static Agents

### Before (Static Agents)
```yaml
# docker-compose-multi-kali.yml
services:
  kali-agent-1:
    container_name: kali-agent-1
    restart: unless-stopped
```

**Issues:**
- Containers always running (resource waste)
- AgentGraph persisted old state
- Old target URLs leaked between scans

### After (Dynamic Containers)
```python
# Containers created on-demand
container_manager.spawn_kali_agents(
    job_id="scan-123",
    target_url="https://example.com",
    num_agents=3
)
```

**Benefits:**
- Containers created only when needed
- Fresh state per scan
- Correct target guaranteed

## Testing

### Test Dynamic Container Lifecycle
```bash
# 1. Start API server
cd fetchbot-platform
python main.py

# 2. In another terminal, trigger a scan
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# 3. Watch containers spawn
watch -n 1 'docker ps --filter "label=managed_by=fetchbot-dynamic"'

# 4. After scan completes, verify cleanup
docker ps -a --filter "label=managed_by=fetchbot-dynamic"
# Should show no containers
```

### Test Multiple Scans
```bash
# Scan 1: example.com
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target": "https://example.com"}'

# Scan 2: test.com (should NOT see example.com in logs)
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target": "https://test.com"}'
```

Verify that:
- ✅ AgentGraph is cleared between scans
- ✅ Each scan gets fresh containers
- ✅ Target URLs don't leak between scans
- ✅ Containers are cleaned up after each scan

## Summary

The dynamic container deployment system solves the state pollution issue by:

1. **Clearing AgentGraph** before each scan
2. **Spawning fresh containers** with target URL in environment
3. **Distributing work** across multiple Kali agents
4. **Cleaning up** containers automatically

This ensures that each scan is isolated and gets the correct target URL, eliminating the confusion where old domains were being read.
