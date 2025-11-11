"""
XSS Agent - Specialized agent for XSS and CSRF testing

Responsibilities:
- Cross-Site Scripting (XSS) testing
- CSRF vulnerability detection
- Client-side injection attacks
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


class XSSAgent(BaseSpecializedAgent):
    """
    Specialized agent for XSS and CSRF testing

    Tools:
    - xss_test
    - csrf_test
    """

    def __init__(self, agent_id: str, orchestrator_url: str, kali_agent_url: str):
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.XSS,
            orchestrator_url=orchestrator_url,
            tools=[
                "xss_test",
                "csrf_test"
            ]
        )
        self.kali_agent_url = kali_agent_url

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an XSS testing tool"""
        logger.info(f"[{self.agent_id}] Executing {tool_name} with params: {params}")

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
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
        return """You are an XSS/CSRF Specialist agent focused on client-side injection vulnerabilities.

Your expertise includes:
- Reflected XSS detection
- Stored XSS detection
- DOM-based XSS
- CSRF token analysis
- Client-side injection attacks

Your tools:
- xss_test: Test for XSS vulnerabilities with various payloads
- csrf_test: Test for CSRF protection

Guidelines:
1. Test all input parameters (GET, POST, URL paths)
2. Use context-aware payloads (HTML, JavaScript, attribute, URL)
3. Test for both reflected and stored XSS
4. Check for proper XSS encoding/sanitization
5. Verify CSRF tokens on state-changing operations
6. Report XSS context (where payload appears in response)
7. Don't execute malicious payloads - just detect reflection
8. Test for DOM-based XSS in JavaScript code
"""


app = FastAPI(title="XSS Agent", version="1.0.0")

AGENT_ID = os.environ.get('AGENT_ID', 'xss-agent-1')
ORCHESTRATOR_URL = os.environ.get('ORCHESTRATOR_URL', 'http://orchestrator:8001')
KALI_AGENT_URL = os.environ.get('KALI_AGENT_URL', 'http://kali-agent:9000')

agent = XSSAgent(
    agent_id=AGENT_ID,
    orchestrator_url=ORCHESTRATOR_URL,
    kali_agent_url=KALI_AGENT_URL
)


@app.on_event("startup")
async def startup():
    logger.info(f"Starting XSS Agent: {AGENT_ID}")

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
    port = int(os.environ.get('AGENT_PORT', 9104))
    uvicorn.run(app, host="0.0.0.0", port=port)
