"""
Fuzzing Agent - Specialized agent for fuzzing and discovery

Responsibilities:
- API endpoint fuzzing
- Directory/file brute forcing
- Parameter fuzzing
- HTTP method testing
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


class FuzzingAgent(BaseSpecializedAgent):
    """
    Specialized agent for fuzzing and discovery

    Tools:
    - api_fuzzing
    - directory_enumeration
    - ffuf_scan
    - gobuster_scan
    - api_method_fuzzing
    """

    def __init__(self, agent_id: str, orchestrator_url: str, kali_agent_url: str):
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.FUZZING,
            orchestrator_url=orchestrator_url,
            tools=[
                "api_fuzzing",
                "directory_enumeration",
                "ffuf_scan",
                "gobuster_scan",
                "api_method_fuzzing"
            ]
        )
        self.kali_agent_url = kali_agent_url

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a fuzzing tool"""
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
        return """You are a Fuzzing Specialist agent focused on discovery through intelligent fuzzing.

Your expertise includes:
- API endpoint fuzzing and parameter manipulation
- Directory and file brute forcing
- Hidden endpoint discovery
- HTTP method enumeration
- Input validation bypass testing

Your tools:
- api_fuzzing: Fuzz API endpoints with various payloads
- directory_enumeration: Discover hidden directories
- ffuf_scan: Fast web fuzzer for directories/files
- gobuster_scan: Directory brute forcing
- api_method_fuzzing: Test all HTTP methods on endpoints

Guidelines:
1. Use intelligent fuzzing - adapt based on responses
2. Look for status code anomalies (200, 403, 500)
3. Test for common backup/debug files (.bak, .old, .backup)
4. Enumerate API versions (v1, v2, api/v1, etc.)
5. Report interesting findings like admin panels, debug endpoints
6. Respect rate limits - don't flood the target
"""


app = FastAPI(title="Fuzzing Agent", version="1.0.0")

AGENT_ID = os.environ.get('AGENT_ID', 'fuzzing-agent-1')
ORCHESTRATOR_URL = os.environ.get('ORCHESTRATOR_URL', 'http://orchestrator:8001')
KALI_AGENT_URL = os.environ.get('KALI_AGENT_URL', 'http://kali-agent:9000')

agent = FuzzingAgent(
    agent_id=AGENT_ID,
    orchestrator_url=ORCHESTRATOR_URL,
    kali_agent_url=KALI_AGENT_URL
)


@app.on_event("startup")
async def startup():
    logger.info(f"Starting Fuzzing Agent: {AGENT_ID}")

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
    port = int(os.environ.get('AGENT_PORT', 9101))
    uvicorn.run(app, host="0.0.0.0", port=port)
