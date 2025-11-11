"""
SQL Injection Agent - Specialized agent for SQL injection testing

Responsibilities:
- SQL injection detection (all techniques)
- sqlmap automation
- Database enumeration
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


class SQLInjectionAgent(BaseSpecializedAgent):
    """
    Specialized agent for SQL injection testing

    Tools:
    - sql_injection_test
    - sqlmap_test
    - database_enumeration
    """

    def __init__(self, agent_id: str, orchestrator_url: str, kali_agent_url: str):
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.SQL_INJECTION,
            orchestrator_url=orchestrator_url,
            tools=[
                "sql_injection_test",
                "sqlmap_test",
                "database_enumeration"
            ]
        )
        self.kali_agent_url = kali_agent_url

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a SQL injection testing tool"""
        logger.info(f"[{self.agent_id}] Executing {tool_name} with params: {params}")

        try:
            # SQLi tests can take longer, especially sqlmap
            timeout = 300.0 if tool_name == "sqlmap_test" else 120.0

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
        return """You are a SQL Injection Specialist agent focused on detecting and exploiting SQL injection vulnerabilities.

Your expertise includes:
- Error-based SQL injection detection
- Boolean-based blind SQLi
- Time-based blind SQLi
- Union-based SQLi
- Database enumeration
- sqlmap automation

Your tools:
- sql_injection_test: Test for SQL injection with specific techniques
- sqlmap_test: Comprehensive sqlmap-based testing
- database_enumeration: Extract database structure

Guidelines:
1. Start with error-based techniques (fastest detection)
2. Use boolean-based for blind SQLi
3. Only use time-based if other methods fail (slowest)
4. Test all input parameters (GET, POST, headers, cookies)
5. Report database type, version, and extracted data
6. If SQLi confirmed, enumerate database structure
7. Never modify or delete data - read-only testing
8. Stop testing a parameter once vulnerability is confirmed
"""


app = FastAPI(title="SQL Injection Agent", version="1.0.0")

AGENT_ID = os.environ.get('AGENT_ID', 'sqli-agent-1')
ORCHESTRATOR_URL = os.environ.get('ORCHESTRATOR_URL', 'http://orchestrator:8001')
KALI_AGENT_URL = os.environ.get('KALI_AGENT_URL', 'http://kali-agent:9000')

agent = SQLInjectionAgent(
    agent_id=AGENT_ID,
    orchestrator_url=ORCHESTRATOR_URL,
    kali_agent_url=KALI_AGENT_URL
)


@app.on_event("startup")
async def startup():
    logger.info(f"Starting SQL Injection Agent: {AGENT_ID}")

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
    port = int(os.environ.get('AGENT_PORT', 9102))
    uvicorn.run(app, host="0.0.0.0", port=port)
