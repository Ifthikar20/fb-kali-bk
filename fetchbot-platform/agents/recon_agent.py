"""
Reconnaissance Agent - Specialized agent for web reconnaissance

Responsibilities:
- HTTP scanning and crawling
- JavaScript analysis for secrets/APIs
- Security headers analysis
- Technology detection
- Exposed file/config detection
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

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
)


class ReconAgent(BaseSpecializedAgent):
    """
    Specialized agent for web reconnaissance

    Tools:
    - http_scan
    - javascript_analysis
    - security_headers_check
    - detect_exposed_env_vars
    - scan_env_files
    """

    def __init__(self, agent_id: str, orchestrator_url: str, kali_agent_url: str):
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.RECON,
            orchestrator_url=orchestrator_url,
            tools=[
                "http_scan",
                "javascript_analysis",
                "security_headers_check",
                "detect_exposed_env_vars",
                "scan_env_files"
            ]
        )
        self.kali_agent_url = kali_agent_url

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a reconnaissance tool"""
        logger.info(f"[{self.agent_id}] Executing {tool_name} with params: {params}")

        try:
            async with httpx.AsyncClient(timeout=180.0) as client:
                response = await client.post(
                    f"{self.kali_agent_url}/execute_tool",
                    json={"tool": tool_name, "params": params}
                )

                if response.status_code == 200:
                    result = response.json()
                    logger.info(f"[{self.agent_id}] {tool_name} completed")
                    return result
                else:
                    error_msg = f"Tool execution failed: {response.status_code}"
                    logger.error(f"[{self.agent_id}] {error_msg}")
                    return {"success": False, "error": error_msg}

        except Exception as e:
            logger.error(f"[{self.agent_id}] Error executing {tool_name}: {e}")
            return {"success": False, "error": str(e)}

    def get_system_prompt(self) -> str:
        return """You are a Web Reconnaissance Specialist agent focused on information gathering and attack surface mapping.

Your expertise includes:
- Web application crawling and endpoint discovery
- JavaScript analysis for API endpoints and secrets
- Technology stack detection
- Security headers analysis
- Exposed configuration and environment files
- Cookie and session analysis

Your tools:
- http_scan: Comprehensive HTTP scan with crawling
- javascript_analysis: Extract APIs and secrets from JS
- security_headers_check: Analyze security headers
- detect_exposed_env_vars: Find exposed environment variables
- scan_env_files: Check for .env, config.php, etc.

Guidelines:
1. Start with http_scan to map the application
2. Analyze all JavaScript files for hardcoded secrets
3. Check for exposed .env, config files, .git directories
4. Report missing security headers
5. Extract API endpoints, forms, and parameters
6. Identify technologies (frameworks, servers, CDNs)
7. Report any hardcoded credentials or API keys
8. Provide structured data for other agents to use
"""


app = FastAPI(title="Recon Agent", version="1.0.0")

AGENT_ID = os.environ.get('AGENT_ID', 'recon-agent-1')
ORCHESTRATOR_URL = os.environ.get('ORCHESTRATOR_URL', 'http://orchestrator:8001')
KALI_AGENT_URL = os.environ.get('KALI_AGENT_URL', 'http://kali-agent:9000')

agent = ReconAgent(
    agent_id=AGENT_ID,
    orchestrator_url=ORCHESTRATOR_URL,
    kali_agent_url=KALI_AGENT_URL
)


@app.on_event("startup")
async def startup():
    logger.info(f"Starting Recon Agent: {AGENT_ID}")

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
        logger.info("Registered with orchestrator")
    except Exception as e:
        logger.warning(f"Could not register: {e}")

    asyncio.create_task(agent.start())


@app.on_event("shutdown")
async def shutdown():
    await agent.stop()


@app.get("/health")
async def health():
    return await agent.health_check()


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get('AGENT_PORT', 9103))
    uvicorn.run(app, host="0.0.0.0", port=port)
