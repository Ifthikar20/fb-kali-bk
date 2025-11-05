"""FetchBot.ai Bot Orchestrator - Claude AI-Powered Decision Engine"""
import asyncio
import httpx
import json
from typing import Dict, List, Optional
from anthropic import Anthropic
from config import get_settings
from datetime import datetime

settings = get_settings()

class BotOrchestrator:
    def __init__(self, org_elastic_ip: str = "localhost"):
        self.org_ip = org_elastic_ip
        self.client = Anthropic(api_key=settings.anthropic_api_key)

        # Bot URLs - use localhost for local docker network
        self.ui_bot_url = "http://ui-bot:8001"
        self.network_bot_url = "http://network-bot:8002"
        self.db_bot_url = "http://db-bot:8003"

        self.all_findings = []
        self.scan_history = []
        self.max_iterations = 5

    async def execute_pentest(self, target: str, mode: str = "discovery") -> Dict:
        """Execute AI-orchestrated pentest with Claude decision-making"""
        print(f"\n{'='*60}")
        print(f"FetchBot.ai AI-Powered Pentest")
        print(f"Target: {target}")
        print(f"Attack IP: {self.org_ip}")
        print(f"Mode: {mode}")
        print(f"{'='*60}\n")

        # Phase 1: Initial reconnaissance with Claude
        print("[PHASE 1] Claude AI: Planning initial reconnaissance...")
        initial_plan = await self._get_initial_scan_plan(target, mode)
        print(f"[CLAUDE] Plan: {initial_plan['reasoning']}\n")

        # Execute initial scans
        for bot_name in initial_plan['bots_to_run']:
            await self._run_bot_scan(bot_name, target, "quick")

        # Phase 2: Iterative scanning based on findings
        iteration = 0
        while iteration < self.max_iterations:
            iteration += 1
            print(f"\n[PHASE 2 - Iteration {iteration}] Claude AI: Analyzing findings...")

            # Ask Claude to analyze findings and decide next steps
            next_action = await self._get_next_action(target, self.all_findings, self.scan_history)

            print(f"[CLAUDE] Decision: {next_action['decision']}")
            print(f"[CLAUDE] Reasoning: {next_action['reasoning']}\n")

            if next_action['action'] == 'stop':
                print("[CLAUDE] Scan complete. No further actions needed.")
                break

            # Execute recommended scans
            for scan_task in next_action.get('scans', []):
                bot_name = scan_task['bot']
                scan_type = scan_task.get('type', 'quick')
                await self._run_bot_scan(bot_name, target, scan_type)

            # Small delay between iterations
            await asyncio.sleep(2)

        # Phase 3: Final analysis and report
        print("\n[PHASE 3] Claude AI: Generating final analysis...")
        final_analysis = await self._generate_final_analysis(target, self.all_findings)

        print(f"\n{'='*60}")
        print(f"Scan Complete!")
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
            'timestamp': datetime.utcnow().isoformat()
        }

    async def _get_initial_scan_plan(self, target: str, mode: str) -> Dict:
        """Ask Claude to plan initial reconnaissance"""

        prompt = f"""You are a penetration testing AI orchestrator for FetchBot.ai.

Target: {target}
Mode: {mode}

Available bots:
- network-bot: Port scanning, service detection, OS fingerprinting, subdomain enumeration
- ui-bot: Web application scanning, XSS, CSRF, security headers, directory enumeration
- db-bot: SQL injection testing, database error detection, NoSQL injection

Your task: Decide which bots to run initially for reconnaissance. Consider:
1. What's the most efficient scanning order?
2. Which scans should run in parallel?
3. What information do we need first?

Respond in JSON format:
{{
    "bots_to_run": ["network-bot", "ui-bot"],  // List of bots to run initially
    "reasoning": "explanation of your decision",
    "parallel": true  // whether to run in parallel
}}"""

        try:
            message = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1024,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            response_text = message.content[0].text

            # Extract JSON from response
            json_match = response_text
            if '```json' in response_text:
                json_match = response_text.split('```json')[1].split('```')[0].strip()
            elif '```' in response_text:
                json_match = response_text.split('```')[1].split('```')[0].strip()

            plan = json.loads(json_match)
            return plan

        except Exception as e:
            print(f"[ERROR] Claude planning error: {e}")
            # Fallback plan
            return {
                'bots_to_run': ['network-bot', 'ui-bot', 'db-bot'],
                'reasoning': 'Using default scan plan due to error',
                'parallel': True
            }

    async def _get_next_action(self, target: str, findings: List[Dict], scan_history: List[Dict]) -> Dict:
        """Ask Claude to analyze findings and decide next actions"""

        # Summarize findings for Claude
        findings_summary = self._summarize_findings(findings)
        history_summary = [{'bot': h['bot'], 'type': h['scan_type'], 'findings_count': h['findings_count']}
                          for h in scan_history]

        prompt = f"""You are a penetration testing AI orchestrator for FetchBot.ai.

Target: {target}

Scan History:
{json.dumps(history_summary, indent=2)}

Current Findings ({len(findings)} total):
{findings_summary}

Available bots:
- network-bot: Port scanning (quick/full), service detection, OS fingerprinting
- ui-bot: Web scanning (quick/full/deep), XSS, CSRF, directory enumeration
- db-bot: SQL injection (quick/full), NoSQL injection, database errors

Your task: Analyze the findings and decide the next action.

Consider:
1. Are there critical findings that need deeper investigation?
2. Do findings suggest specific attacks to try next?
3. Have we scanned thoroughly enough?
4. Should we run deeper scans on specific areas?
5. Are we wasting time on unproductive scans?

Respond in JSON format:
{{
    "action": "continue" or "stop",
    "decision": "brief decision summary",
    "reasoning": "detailed reasoning for your decision",
    "scans": [
        {{"bot": "network-bot", "type": "full", "reason": "why run this scan"}},
        ...
    ]
}}

If no further scans are needed, use action: "stop"."""

        try:
            message = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1536,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            response_text = message.content[0].text

            # Extract JSON
            json_match = response_text
            if '```json' in response_text:
                json_match = response_text.split('```json')[1].split('```')[0].strip()
            elif '```' in response_text:
                json_match = response_text.split('```')[1].split('```')[0].strip()

            action = json.loads(json_match)
            return action

        except Exception as e:
            print(f"[ERROR] Claude decision error: {e}")
            # Fallback: stop scanning
            return {
                'action': 'stop',
                'decision': 'Stopping due to error',
                'reasoning': f'Error in Claude analysis: {e}',
                'scans': []
            }

    async def _generate_final_analysis(self, target: str, findings: List[Dict]) -> str:
        """Ask Claude to generate final security analysis"""

        findings_by_severity = {
            'critical': [f for f in findings if f.get('severity') == 'critical'],
            'high': [f for f in findings if f.get('severity') == 'high'],
            'medium': [f for f in findings if f.get('severity') == 'medium'],
            'low': [f for f in findings if f.get('severity') == 'low'],
            'info': [f for f in findings if f.get('severity') == 'info']
        }

        prompt = f"""You are a senior security analyst reviewing a penetration test.

Target: {target}
Total Findings: {len(findings)}

Findings Summary:
- Critical: {len(findings_by_severity['critical'])}
- High: {len(findings_by_severity['high'])}
- Medium: {len(findings_by_severity['medium'])}
- Low: {len(findings_by_severity['low'])}
- Info: {len(findings_by_severity['info'])}

Critical Findings:
{json.dumps([f['title'] for f in findings_by_severity['critical'][:10]], indent=2)}

High Findings:
{json.dumps([f['title'] for f in findings_by_severity['high'][:10]], indent=2)}

Provide a concise executive summary including:
1. Overall security posture
2. Most critical risks
3. Recommended immediate actions
4. Priority order for remediation

Keep it professional and actionable (300-500 words)."""

        try:
            message = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2048,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            return message.content[0].text

        except Exception as e:
            print(f"[ERROR] Claude analysis error: {e}")
            return f"Analysis generation failed: {e}"

    async def _run_bot_scan(self, bot_name: str, target: str, scan_type: str = "quick") -> Optional[Dict]:
        """Execute a specific bot scan"""

        bot_urls = {
            'network-bot': self.network_bot_url,
            'ui-bot': self.ui_bot_url,
            'db-bot': self.db_bot_url
        }

        if bot_name not in bot_urls:
            print(f"[ERROR] Unknown bot: {bot_name}")
            return None

        bot_url = bot_urls[bot_name]

        print(f"[SCANNING] {bot_name} ({scan_type}) on {target}...")

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{bot_url}/scan",
                    json={"target": target, "scan_type": scan_type}
                )

                if response.status_code == 200:
                    result = response.json()
                    findings = result.get('findings', [])

                    # Add discovered_by to each finding
                    for finding in findings:
                        finding['discovered_by'] = bot_name

                    self.all_findings.extend(findings)

                    # Record scan history
                    self.scan_history.append({
                        'bot': bot_name,
                        'scan_type': scan_type,
                        'target': target,
                        'findings_count': len(findings),
                        'timestamp': datetime.utcnow().isoformat()
                    })

                    print(f"[{bot_name}] Found {len(findings)} items")

                    # Show critical/high findings
                    critical_high = [f for f in findings if f.get('severity') in ['critical', 'high']]
                    for finding in critical_high[:3]:  # Show first 3
                        print(f"  [{finding.get('severity', 'unknown').upper()}] {finding.get('title', 'Unknown')}")

                    return result
                else:
                    print(f"[ERROR] {bot_name} returned status {response.status_code}")
                    return None

        except Exception as e:
            print(f"[ERROR] Failed to scan with {bot_name}: {e}")
            return None

    def _summarize_findings(self, findings: List[Dict], max_items: int = 20) -> str:
        """Create a concise summary of findings for Claude"""

        if not findings:
            return "No findings yet."

        # Group by severity
        by_severity = {}
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        summary_parts = []

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity in by_severity:
                items = by_severity[severity]
                summary_parts.append(f"\n{severity.upper()} ({len(items)}):")

                # Show details for critical/high, just titles for others
                show_count = 5 if severity in ['critical', 'high'] else 3

                for item in items[:show_count]:
                    title = item.get('title', 'Unknown')
                    item_type = item.get('type', 'unknown')
                    bot = item.get('discovered_by', 'unknown')
                    summary_parts.append(f"  - {title} (type: {item_type}, by: {bot})")

                if len(items) > show_count:
                    summary_parts.append(f"  ... and {len(items) - show_count} more")

        return "\n".join(summary_parts)
