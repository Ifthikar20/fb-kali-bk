"""
Authentication Agent - Specialized agent for authentication/authorization testing

Responsibilities:
- Brute force attacks
- IDOR testing
- Privilege escalation
- Rate limiting verification
- Authentication bypass
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


class AuthAgent(BaseSpecializedAgent):
    """
    Specialized agent for authentication and authorization testing

    Tools:
    - api_brute_force
    - api_rate_limit_test
    - api_privilege_escalation_test
    - api_idor_test
    """

    def __init__(self, agent_id: str, orchestrator_url: str, kali_agent_url: str):
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.AUTH,
            orchestrator_url=orchestrator_url,
            tools=[
                "api_brute_force",
                "api_rate_limit_test",
                "api_privilege_escalation_test",
                "api_idor_test"
            ]
        )
        self.kali_agent_url = kali_agent_url

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an authentication testing tool"""
        logger.info(f"[{self.agent_id}] Executing {tool_name} with params: {params}")

        try:
            # Brute force can take longer
            timeout = 300.0 if tool_name == "api_brute_force" else 120.0

            async with httpx.AsyncClient(timeout=timeout) as client:
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
        return """You are an Authentication/Authorization Specialist agent focused on access control vulnerabilities.

Your expertise includes:
- Authentication brute forcing
- Insecure Direct Object Reference (IDOR)
- Privilege escalation
- Rate limiting bypass
- Session management flaws
- Authorization bypass

Your tools:
- api_brute_force: Brute force authentication endpoints
- api_rate_limit_test: Test for rate limiting
- api_privilege_escalation_test: Test for privilege escalation
- api_idor_test: Test for IDOR vulnerabilities

Guidelines:
1. Always test for rate limiting BEFORE brute forcing
2. Use small password lists first (don't flood the target)
3. Test IDOR by accessing other users' data
4. Check horizontal privilege escalation (user → user)
5. Check vertical privilege escalation (user → admin)
6. Verify proper session invalidation
7. Test for authentication bypass techniques
8. Report missing rate limiting as high severity
9. Stop brute forcing if rate limiting is detected
10. Never attempt to cause account lockouts
"""


app = FastAPI(title="Auth Agent", version="1.0.0")

AGENT_ID = os.environ.get('AGENT_ID', 'auth-agent-1')
ORCHESTRATOR_URL = os.environ.get('ORCHESTRATOR_URL', 'http://orchestrator:8001')
KALI_AGENT_URL = os.environ.get('KALI_AGENT_URL', 'http://kali-agent:9000')

agent = AuthAgent(
    agent_id=AGENT_ID,
    orchestrator_url=ORCHESTRATOR_URL,
    kali_agent_url=KALI_AGENT_URL
)


@app.on_event("startup")
async def startup():
    logger.info(f"Starting Auth Agent: {AGENT_ID}")

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
    port = int(os.environ.get('AGENT_PORT', 9105))
    uvicorn.run(app, host="0.0.0.0", port=port)
