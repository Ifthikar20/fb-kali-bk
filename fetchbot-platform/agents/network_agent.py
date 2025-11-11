"""
Network Agent - Specialized agent for network reconnaissance

Responsibilities:
- Port scanning (nmap)
- Service detection
- DNS enumeration
- OS fingerprinting
"""

import os
import asyncio
import httpx
import logging
from typing import Dict, Any

import sys
sys.path.insert(0, '/app')

from core.agents.specialized_agent_base import BaseSpecializedAgent, AgentType
from fastapi import FastAPI

logger = logging.getLogger(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
)


class NetworkAgent(BaseSpecializedAgent):
    """
    Specialized agent for network security testing

    Tools:
    - nmap_scan
    - nmap_detailed_scan
    - dns_enumerate
    - service_detection
    """

    def __init__(self, agent_id: str, orchestrator_url: str, kali_agent_url: str):
        """
        Initialize Network Agent

        Args:
            agent_id: Unique agent identifier
            orchestrator_url: URL of the orchestrator
            kali_agent_url: URL of the Kali container's tool server
        """
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.NETWORK,
            orchestrator_url=orchestrator_url,
            tools=[
                "nmap_scan",
                "nmap_detailed_scan",
                "dns_enumerate",
                "service_detection"
            ]
        )
        self.kali_agent_url = kali_agent_url

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a network security tool

        Args:
            tool_name: Name of the tool (e.g., nmap_scan)
            params: Tool parameters

        Returns:
            Tool execution result
        """
        logger.info(f"[{self.agent_id}] Executing {tool_name} with params: {params}")

        try:
            # Call Kali container's tool execution endpoint
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{self.kali_agent_url}/execute_tool",
                    json={
                        "tool": tool_name,
                        "params": params
                    }
                )

                if response.status_code == 200:
                    result = response.json()
                    logger.info(f"[{self.agent_id}] {tool_name} completed successfully")
                    return result
                else:
                    error_msg = f"Tool execution failed: {response.status_code}"
                    logger.error(f"[{self.agent_id}] {error_msg}")
                    return {"success": False, "error": error_msg}

        except Exception as e:
            logger.error(f"[{self.agent_id}] Error executing {tool_name}: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    def get_system_prompt(self) -> str:
        """Get system prompt for Network Agent"""
        return """You are a Network Security Specialist agent focused on network reconnaissance.

Your expertise includes:
- Port scanning and service detection using nmap
- DNS enumeration and subdomain discovery
- Network topology mapping
- OS fingerprinting
- Service version detection
- Identifying exposed network services

Your tools:
- nmap_scan: Quick port scan (top 1000 ports)
- nmap_detailed_scan: Comprehensive scan with service detection
- dns_enumerate: DNS record enumeration
- service_detection: Detect services on specific ports

Guidelines:
1. Start with quick scans, then do detailed scans on interesting findings
2. Identify all open ports and running services
3. Detect service versions for vulnerability correlation
4. Enumerate DNS records for complete attack surface mapping
5. Report high-risk services (telnet, FTP, unencrypted databases)
6. Never perform DoS attacks or flood the target
"""


# FastAPI app for the agent
app = FastAPI(title="Network Agent", version="1.0.0")

# Get configuration from environment
AGENT_ID = os.environ.get('AGENT_ID', 'network-agent-1')
ORCHESTRATOR_URL = os.environ.get('ORCHESTRATOR_URL', 'http://orchestrator:8001')
KALI_AGENT_URL = os.environ.get('KALI_AGENT_URL', 'http://kali-agent:9000')

# Create agent instance
agent = NetworkAgent(
    agent_id=AGENT_ID,
    orchestrator_url=ORCHESTRATOR_URL,
    kali_agent_url=KALI_AGENT_URL
)


@app.on_event("startup")
async def startup():
    """Start agent on startup"""
    logger.info(f"Starting Network Agent: {AGENT_ID}")

    # Register with orchestrator
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{ORCHESTRATOR_URL}/agents/register",
                json={
                    "agent_id": agent.agent_id,
                    "agent_type": agent.agent_type.value,
                    "tools": list(agent.tools)
                }
            )
        logger.info(f"Registered with orchestrator: {ORCHESTRATOR_URL}")
    except Exception as e:
        logger.warning(f"Could not register with orchestrator: {e}")

    # Start agent work loop in background
    asyncio.create_task(agent.start())


@app.on_event("shutdown")
async def shutdown():
    """Stop agent on shutdown"""
    logger.info(f"Shutting down Network Agent: {AGENT_ID}")
    await agent.stop()


@app.get("/health")
async def health():
    """Health check endpoint"""
    return await agent.health_check()


@app.get("/status")
async def status():
    """Get agent status"""
    return await agent.health_check()


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get('AGENT_PORT', 9100))
    uvicorn.run(app, host="0.0.0.0", port=port)
