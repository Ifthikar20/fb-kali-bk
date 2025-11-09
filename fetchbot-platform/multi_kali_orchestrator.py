"""FetchBot.ai Multi-Kali Orchestrator - Manages Multiple Kali Containers"""
import asyncio
import httpx
import json
from typing import Dict, List, Optional
from anthropic import Anthropic
from config import get_settings
from datetime import datetime

settings = get_settings()

class MultiKaliOrchestrator:
    """Orchestrates multiple Kali Linux containers with Claude AI"""

    def __init__(self, org_elastic_ip: str = "localhost", num_agents: int = 3):
        self.org_ip = org_elastic_ip
        self.client = Anthropic(api_key=settings.anthropic_api_key)
        self.num_agents = num_agents

        # Kali agent URLs (in docker network)
        self.kali_agents = []
        for i in range(1, num_agents + 1):
            self.kali_agents.append({
                'id': f'kali-agent-{i}',
                'url': f'http://kali-agent-{i}:9000',
                'busy': False
            })

        self.all_findings = []
        self.scan_history = []
        self.max_iterations = 5

    async def execute_pentest(self, target: str, mode: str = "discovery") -> Dict:
        """Execute AI-orchestrated pentest with multiple Kali containers"""
        print(f"\n{'='*60}")
        print(f"FetchBot.ai Multi-Kali AI-Powered Pentest")
        print(f"Target: {target}")
        print(f"Attack IP: {self.org_ip}")
        print(f"Available Kali Agents: {self.num_agents}")
        print(f"Mode: {mode}")
        print(f"{'='*60}\n")

        # Phase 1: Claude plans initial strategy
        print("[PHASE 1] Claude AI: Planning reconnaissance strategy...")
        initial_plan = await self._get_initial_scan_plan(target, mode)
        print(f"[CLAUDE] Strategy: {initial_plan['reasoning']}\n")

        # Execute initial scans in parallel across Kali containers
        await self._execute_parallel_scans(target, initial_plan['scan_tasks'])

        # Phase 2: Iterative analysis and deeper scanning
        iteration = 0
        while iteration < self.max_iterations:
            iteration += 1
            print(f"\n[PHASE 2 - Iteration {iteration}] Claude AI: Analyzing {len(self.all_findings)} findings...")

            # Ask Claude what to do next
            next_action = await self._get_next_action(target, self.all_findings, self.scan_history)

            print(f"[CLAUDE] Decision: {next_action['decision']}")
            print(f"[CLAUDE] Reasoning: {next_action['reasoning']}\n")

            if next_action['action'] == 'stop':
                print("[CLAUDE] Assessment complete.")
                break

            # Execute recommended scans
            scan_tasks = next_action.get('scan_tasks', [])
            if scan_tasks:
                await self._execute_parallel_scans(target, scan_tasks)

            await asyncio.sleep(1)

        # Phase 3: Final analysis
        print("\n[PHASE 3] Claude AI: Generating comprehensive analysis...")
        final_analysis = await self._generate_final_analysis(target, self.all_findings)

        print(f"\n{'='*60}")
        print(f"Pentest Complete!")
        print(f"Total Findings: {len(self.all_findings)}")
        print(f"Critical: {sum(1 for f in self.all_findings if f.get('severity') == 'critical')}")
        print(f"High: {sum(1 for f in self.all_findings if f.get('severity') == 'high')}")
        print(f"Medium: {sum(1 for f in self.all_findings if f.get('severity') == 'medium')}")
        print(f"{'='*60}\n")

        return {
            'target': target,
            'attack_ip': self.org_ip,
            'findings': self.all_findings,
            'analysis': final_analysis,
            'scan_history': self.scan_history,
            'agents_used': self.num_agents,
            'timestamp': datetime.utcnow().isoformat()
        }

    async def _get_initial_scan_plan(self, target: str, mode: str) -> Dict:
        """Ask Claude to plan initial scanning strategy"""

        prompt = f"""You are a penetration testing AI orchestrator for FetchBot.ai.

Target: {target}
Mode: {mode}
Available Agents: {self.num_agents} Kali Linux containers (can run in parallel)

Each Kali agent can perform:
- network: Port scanning (nmap), service detection, DNS enumeration
- web: XSS, CSRF, security headers, directory enumeration, nikto
- database: SQL injection, NoSQL injection, database errors

Your task: Plan the initial reconnaissance strategy.

Consider:
1. Which scan types should run first?
2. Can we run multiple scans in parallel?
3. What's the most efficient approach?

Respond in JSON:
{{
    "scan_tasks": [
        {{"scan_type": "network", "depth": "quick"}},
        {{"scan_type": "web", "depth": "quick"}}
    ],
    "reasoning": "Start with parallel network and web reconnaissance",
    "parallel": true
}}"""

        try:
            message = self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text
            json_match = response_text

            if '```json' in response_text:
                json_match = response_text.split('```json')[1].split('```')[0].strip()
            elif '```' in response_text:
                json_match = response_text.split('```')[1].split('```')[0].strip()

            plan = json.loads(json_match)
            return plan

        except Exception as e:
            print(f"[ERROR] Claude planning error: {e}")
            return {
                'scan_tasks': [
                    {'scan_type': 'network', 'depth': 'quick'},
                    {'scan_type': 'web', 'depth': 'quick'}
                ],
                'reasoning': 'Using default strategy',
                'parallel': True
            }

    async def _get_next_action(self, target: str, findings: List[Dict], scan_history: List[Dict]) -> Dict:
        """Ask Claude to analyze and decide next steps"""

        findings_summary = self._summarize_findings(findings)
        history_summary = [
            {'agent': h.get('agent_id', 'unknown'), 'scan_type': h['scan_type'], 'findings': h['findings_count']}
            for h in scan_history
        ]

        prompt = f"""You are a penetration testing AI orchestrator for FetchBot.ai.

Target: {target}
Available Agents: {self.num_agents} Kali containers

Scan History:
{json.dumps(history_summary, indent=2)}

Current Findings ({len(findings)} total):
{findings_summary}

Your task: Decide what to scan next.

Consider:
1. Do findings suggest specific vulnerabilities to investigate deeper?
2. Are there critical findings that need verification?
3. Have we covered all major attack surfaces?
4. Should we stop or continue?

Respond in JSON:
{{
    "action": "continue" or "stop",
    "decision": "brief summary",
    "reasoning": "detailed reasoning",
    "scan_tasks": [
        {{"scan_type": "database", "depth": "deep"}},
        ...
    ]
}}"""

        try:
            message = self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=1536,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text
            json_match = response_text

            if '```json' in response_text:
                json_match = response_text.split('```json')[1].split('```')[0].strip()
            elif '```' in response_text:
                json_match = response_text.split('```')[1].split('```')[0].strip()

            action = json.loads(json_match)
            return action

        except Exception as e:
            print(f"[ERROR] Claude decision error: {e}")
            return {
                'action': 'stop',
                'decision': 'Error in analysis',
                'reasoning': f'Error: {e}',
                'scan_tasks': []
            }

    async def _generate_final_analysis(self, target: str, findings: List[Dict]) -> str:
        """Ask Claude for final security analysis"""

        by_severity = {
            'critical': [f for f in findings if f.get('severity') == 'critical'],
            'high': [f for f in findings if f.get('severity') == 'high'],
            'medium': [f for f in findings if f.get('severity') == 'medium'],
            'low': [f for f in findings if f.get('severity') == 'low'],
            'info': [f for f in findings if f.get('severity') == 'info']
        }

        prompt = f"""Senior security analyst review for penetration test.

Target: {target}
Total Findings: {len(findings)}

Summary:
- Critical: {len(by_severity['critical'])}
- High: {len(by_severity['high'])}
- Medium: {len(by_severity['medium'])}
- Low: {len(by_severity['low'])}
- Info: {len(by_severity['info'])}

Critical Findings:
{json.dumps([f['title'] for f in by_severity['critical'][:10]], indent=2)}

High Findings:
{json.dumps([f['title'] for f in by_severity['high'][:10]], indent=2)}

Provide executive summary:
1. Overall security posture
2. Critical risks
3. Immediate actions
4. Remediation priority

Keep professional and actionable (300-500 words)."""

        try:
            message = self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}]
            )

            return message.content[0].text

        except Exception as e:
            return f"Analysis failed: {e}"

    async def _execute_parallel_scans(self, target: str, scan_tasks: List[Dict]):
        """Execute multiple scans in parallel across available Kali containers"""

        print(f"[ORCHESTRATOR] Executing {len(scan_tasks)} scan(s) in parallel...")

        # Create async tasks for each scan
        tasks = []
        for i, task in enumerate(scan_tasks):
            # Get available agent
            agent = self.kali_agents[i % self.num_agents]
            scan_type = task.get('scan_type', 'network')
            depth = task.get('depth', 'quick')

            tasks.append(self._run_kali_scan(agent, target, scan_type, depth))

        # Execute all in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        print(f"[ORCHESTRATOR] Completed {len(tasks)} scan(s)")

    async def _run_kali_scan(self, agent: Dict, target: str, scan_type: str, depth: str = "quick") -> Optional[Dict]:
        """Execute scan on specific Kali agent"""

        agent_id = agent['id']
        agent_url = agent['url']

        print(f"[{agent_id}] Starting {scan_type} scan ({depth}) on {target}...")

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{agent_url}/scan",
                    json={"target": target, "scan_type": scan_type, "depth": depth}
                )

                if response.status_code == 200:
                    result = response.json()
                    findings = result.get('findings', [])

                    # Add agent info to findings
                    for finding in findings:
                        finding['discovered_by'] = agent_id

                    self.all_findings.extend(findings)

                    # Record scan history
                    self.scan_history.append({
                        'agent_id': agent_id,
                        'scan_type': scan_type,
                        'depth': depth,
                        'target': target,
                        'findings_count': len(findings),
                        'timestamp': datetime.utcnow().isoformat()
                    })

                    print(f"[{agent_id}] Found {len(findings)} items")

                    # Show critical/high
                    critical_high = [f for f in findings if f.get('severity') in ['critical', 'high']]
                    for finding in critical_high[:2]:
                        print(f"  [{finding.get('severity', '').upper()}] {finding.get('title', '')}")

                    return result
                else:
                    print(f"[ERROR] {agent_id} returned {response.status_code}")
                    return None

        except Exception as e:
            print(f"[ERROR] {agent_id} scan failed: {e}")
            return None

    def _summarize_findings(self, findings: List[Dict]) -> str:
        """Summarize findings for Claude"""

        if not findings:
            return "No findings yet."

        by_severity = {}
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        parts = []

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity in by_severity:
                items = by_severity[severity]
                parts.append(f"\n{severity.upper()} ({len(items)}):")

                show_count = 5 if severity in ['critical', 'high'] else 3

                for item in items[:show_count]:
                    title = item.get('title', 'Unknown')
                    item_type = item.get('type', 'unknown')
                    parts.append(f"  - {title} (type: {item_type})")

                if len(items) > show_count:
                    parts.append(f"  ... and {len(items) - show_count} more")

        return "\n".join(parts)
