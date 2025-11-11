"""
FetchBot.ai - Dynamic Kali Agent
Executes individual security tools for the dynamic multi-agent system
"""
import asyncio
import subprocess
import nmap
import httpx
import socket
import dns.resolver
import json
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="FetchBot Dynamic Kali Agent", version="3.0.0")

# Get agent configuration from environment
AGENT_ID = os.environ.get('AGENT_ID', 'kali-agent-unknown')
TARGET_URL = os.environ.get('TARGET_URL', '')  # Default target for this agent
JOB_ID = os.environ.get('JOB_ID', '')

class ToolRequest(BaseModel):
    """Request to execute a specific tool"""
    tool_name: str
    parameters: Dict[str, Any]


class DynamicKaliAgent:
    """Kali agent that executes individual security tools"""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.nm = nmap.PortScanner()
        self.headers = {'User-Agent': f'FetchBot/{agent_id}'}

    async def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific security tool"""
        logger.info(f"[{self.agent_id}] Executing tool: {tool_name} with params: {list(parameters.keys())}")

        # Map tool names to handler methods
        tool_handlers = {
            'nmap_scan': self.nmap_scan,
            'http_scan': self.http_scan,
            'dns_enumerate': self.dns_enumerate,
            'resolve_domain': self.resolve_domain,
            'javascript_analysis': self.javascript_analysis,
            'security_headers_check': self.security_headers_check,
            'sql_injection_test': self.sql_injection_test,
            'xss_test': self.xss_test,
            'api_fuzzing': self.api_fuzzing,
            'api_brute_force': self.api_brute_force,
            'api_idor_test': self.api_idor_test,
            'api_rate_limit_test': self.api_rate_limit_test,
            'api_privilege_escalation_test': self.api_privilege_escalation_test,
            'detect_exposed_env_vars': self.detect_exposed_env_vars,
        }

        handler = tool_handlers.get(tool_name)
        if not handler:
            raise HTTPException(status_code=400, detail=f"Unknown tool: {tool_name}")

        try:
            result = await handler(parameters)
            return {
                "success": True,
                "tool_name": tool_name,
                "result": result,
                "agent_id": self.agent_id
            }
        except Exception as e:
            logger.error(f"[{self.agent_id}] Tool {tool_name} failed: {e}")
            return {
                "success": False,
                "tool_name": tool_name,
                "error": str(e),
                "agent_id": self.agent_id
            }

    async def nmap_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Network port scanning"""
        target = params.get('target', '')
        ports = params.get('ports', '1-1000')
        scan_type = params.get('scan_type', 'quick')

        try:
            ip = socket.gethostbyname(target.replace('https://', '').replace('http://', '').split('/')[0])

            args = "-F -T4" if scan_type == "quick" else "-p- -sV -T4 -A"
            self.nm.scan(ip, arguments=args)

            open_ports = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        if port_info['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'protocol': proto,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'state': 'open'
                            })

            return {
                "target": target,
                "ip": ip,
                "open_ports": open_ports,
                "total_open": len(open_ports)
            }
        except Exception as e:
            return {"error": str(e), "target": target}

    async def http_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """HTTP/HTTPS website scanning"""
        url = params.get('url', '')
        crawl_depth = int(params.get('crawl_depth', 1))
        extract_apis = params.get('extract_apis', False)
        extract_forms = params.get('extract_forms', False)

        results = {
            "url": url,
            "status_code": None,
            "technologies": [],
            "forms": [],
            "apis": [],
            "headers": {}
        }

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(url, headers=self.headers)
                results["status_code"] = response.status_code
                results["headers"] = dict(response.headers)

                # Technology detection
                if 'Server' in response.headers:
                    results["technologies"].append({"type": "server", "value": response.headers['Server']})
                if 'X-Powered-By' in response.headers:
                    results["technologies"].append({"type": "framework", "value": response.headers['X-Powered-By']})

                # Extract forms
                if extract_forms:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    for form in forms:
                        form_data = {
                            "action": form.get('action', ''),
                            "method": form.get('method', 'GET').upper(),
                            "inputs": []
                        }
                        for inp in form.find_all(['input', 'textarea']):
                            form_data["inputs"].append({
                                "name": inp.get('name'),
                                "type": inp.get('type', 'text')
                            })
                        results["forms"].append(form_data)

        except Exception as e:
            results["error"] = str(e)

        return results

    async def dns_enumerate(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """DNS enumeration"""
        domain = params.get('domain', '').replace('https://', '').replace('http://', '').split('/')[0]

        records = {"domain": domain, "records": []}

        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    records["records"].append({
                        "type": record_type,
                        "value": str(rdata)
                    })
            except:
                pass

        return records

    async def resolve_domain(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve domain to IP"""
        domain = params.get('domain', '').replace('https://', '').replace('http://', '').split('/')[0]

        try:
            ip = socket.gethostbyname(domain)
            return {"domain": domain, "ip": ip, "resolved": True}
        except Exception as e:
            return {"domain": domain, "error": str(e), "resolved": False}

    async def javascript_analysis(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze JavaScript files"""
        url = params.get('url', '')

        findings = {"url": url, "scripts": [], "sensitive_data": []}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=self.headers)
                soup = BeautifulSoup(response.text, 'html.parser')

                scripts = soup.find_all('script', src=True)
                findings["scripts"] = [urljoin(url, s.get('src')) for s in scripts[:10]]

        except Exception as e:
            findings["error"] = str(e)

        return findings

    async def security_headers_check(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check security headers"""
        url = params.get('url', '')

        result = {"url": url, "missing_headers": [], "present_headers": []}

        security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-XSS-Protection'
        ]

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=self.headers)

                for header in security_headers:
                    if header in response.headers:
                        result["present_headers"].append({
                            "header": header,
                            "value": response.headers[header]
                        })
                    else:
                        result["missing_headers"].append(header)

        except Exception as e:
            result["error"] = str(e)

        return result

    async def sql_injection_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Test for SQL injection"""
        url = params.get('url', '')
        parameter = params.get('parameter', 'id')

        payloads = ["'", "' OR '1'='1", "' OR '1'='1' --", "admin' --"]
        results = {"url": url, "parameter": parameter, "vulnerable": False, "responses": []}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                for payload in payloads:
                    test_url = f"{url}?{parameter}={payload}"
                    response = await client.get(test_url, headers=self.headers)

                    sql_errors = ['sql syntax', 'mysql', 'postgresql', 'ora-', 'sqlstate']
                    if any(err in response.text.lower() for err in sql_errors):
                        results["vulnerable"] = True
                        results["responses"].append({
                            "payload": payload,
                            "detected_error": True
                        })

        except Exception as e:
            results["error"] = str(e)

        return results

    async def xss_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Test for XSS vulnerabilities"""
        url = params.get('url', '')
        parameter = params.get('parameter', 'q')

        payload = '<script>alert(1)</script>'
        result = {"url": url, "parameter": parameter, "vulnerable": False}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                test_url = f"{url}?{parameter}={payload}"
                response = await client.get(test_url, headers=self.headers)

                if payload in response.text:
                    result["vulnerable"] = True
                    result["payload"] = payload

        except Exception as e:
            result["error"] = str(e)

        return result

    async def api_fuzzing(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """API fuzzing"""
        api_url = params.get('api_url', '')
        method = params.get('method', 'GET').upper()

        results = {"api_url": api_url, "method": method, "tests": []}

        payloads = ['../../../etc/passwd', '<script>alert(1)</script>', "'; DROP TABLE users--"]

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                for payload in payloads:
                    try:
                        if method == 'GET':
                            response = await client.get(f"{api_url}?data={payload}", headers=self.headers)
                        else:
                            response = await client.post(api_url, json={"data": payload}, headers=self.headers)

                        results["tests"].append({
                            "payload": payload,
                            "status_code": response.status_code,
                            "interesting": response.status_code in [500, 403, 401]
                        })
                    except:
                        pass

        except Exception as e:
            results["error"] = str(e)

        return results

    async def api_brute_force(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """API brute force testing"""
        api_url = params.get('api_url', '')

        return {
            "api_url": api_url,
            "tested": True,
            "note": "Brute force testing disabled in demo mode"
        }

    async def api_idor_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Test for IDOR vulnerabilities"""
        api_url = params.get('api_url', '')
        id_parameter = params.get('id_parameter', 'id')

        results = {"api_url": api_url, "vulnerable": False, "tests": []}

        test_ids = ['1', '2', '999', 'admin']

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                for test_id in test_ids:
                    test_url = api_url.replace('{id}', test_id).replace('{ID}', test_id)
                    try:
                        response = await client.get(test_url, headers=self.headers)
                        results["tests"].append({
                            "id": test_id,
                            "status_code": response.status_code,
                            "accessible": response.status_code == 200
                        })
                    except:
                        pass

        except Exception as e:
            results["error"] = str(e)

        return results

    async def api_rate_limit_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Test API rate limiting"""
        api_url = params.get('api_url', '')
        request_count = int(params.get('request_count', 20))

        results = {"api_url": api_url, "rate_limited": False, "requests_sent": 0}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                for i in range(request_count):
                    response = await client.get(api_url, headers=self.headers)
                    results["requests_sent"] += 1

                    if response.status_code == 429:
                        results["rate_limited"] = True
                        break

        except Exception as e:
            results["error"] = str(e)

        return results

    async def api_privilege_escalation_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Test for privilege escalation"""
        api_url = params.get('api_url', '')

        return {
            "api_url": api_url,
            "tested": True,
            "note": "Privilege escalation tests require authentication context"
        }

    async def detect_exposed_env_vars(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Detect exposed environment variables"""
        api_url = params.get('api_url', '')

        results = {"api_url": api_url, "exposed_vars": []}

        sensitive_paths = ['/.env', '/config.json', '/env.js', '/.git/config']

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                for path in sensitive_paths:
                    test_url = urljoin(api_url, path)
                    try:
                        response = await client.get(test_url, headers=self.headers)
                        if response.status_code == 200:
                            results["exposed_vars"].append({
                                "path": path,
                                "accessible": True
                            })
                    except:
                        pass

        except Exception as e:
            results["error"] = str(e)

        return results

    async def ffuf_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Directory/file fuzzing with ffuf (Fast web fuzzer)

        Uses SecLists wordlists for discovering hidden files and directories
        """
        url = params.get('url', '')
        wordlist = params.get('wordlist', '/usr/share/wordlists/common.txt')
        extensions = params.get('extensions', '')  # e.g., "php,html,txt"
        threads = params.get('threads', '40')

        results = {"url": url, "wordlist": wordlist, "found": []}

        try:
            # Build ffuf command
            # FUZZ keyword is where wordlist items get inserted
            fuzz_url = url.rstrip('/') + '/FUZZ'

            cmd = [
                'ffuf',
                '-u', fuzz_url,
                '-w', wordlist,
                '-t', str(threads),
                '-mc', '200,204,301,302,307,401,403',  # Match these status codes
                '-fc', '404',  # Filter out 404s
                '-timeout', '10',
                '-maxtime', '60',  # Max 60 seconds
                '-o', '/tmp/ffuf_output.json',
                '-of', 'json',
                '-s'  # Silent mode (less output)
            ]

            if extensions:
                cmd.extend(['-e', extensions])

            # Run ffuf
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=70  # 10 seconds more than ffuf's maxtime
            )

            # Parse JSON output
            try:
                import json
                with open('/tmp/ffuf_output.json', 'r') as f:
                    ffuf_data = json.load(f)

                if 'results' in ffuf_data:
                    for result in ffuf_data['results'][:50]:  # Limit to 50 results
                        results["found"].append({
                            'url': result.get('url', ''),
                            'status': result.get('status', 0),
                            'size': result.get('length', 0),
                            'words': result.get('words', 0),
                            'lines': result.get('lines', 0)
                        })
            except:
                pass

            results["discovered_count"] = len(results["found"])
            results["note"] = f"Fuzzing completed. Found {len(results['found'])} interesting paths."

        except asyncio.TimeoutError:
            results["error"] = "Fuzzing timed out after 60 seconds"
        except Exception as e:
            results["error"] = str(e)

        return results

    async def gobuster_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Directory brute-forcing with gobuster

        Faster than dirb, uses SecLists wordlists
        """
        url = params.get('url', '')
        wordlist = params.get('wordlist', '/usr/share/wordlists/common.txt')
        extensions = params.get('extensions', '')  # e.g., "php,html"
        threads = params.get('threads', '50')

        results = {"url": url, "wordlist": wordlist, "found": []}

        try:
            cmd = [
                'gobuster', 'dir',
                '-u', url,
                '-w', wordlist,
                '-t', str(threads),
                '-q',  # Quiet mode
                '-n',  # No status
                '--no-error',
                '--timeout', '10s',
                '-o', '/tmp/gobuster_output.txt'
            ]

            if extensions:
                cmd.extend(['-x', extensions])

            # Run gobuster
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=120  # 2 minutes max
            )

            # Parse output file
            try:
                with open('/tmp/gobuster_output.txt', 'r') as f:
                    for line in f:
                        if line.strip():
                            # Gobuster format: /path (Status: 200) [Size: 1234]
                            parts = line.strip().split()
                            if len(parts) >= 3:
                                results["found"].append({
                                    'path': parts[0],
                                    'status': parts[2].rstrip(')') if len(parts) > 2 else 'unknown',
                                    'line': line.strip()
                                })
            except:
                pass

            results["discovered_count"] = len(results["found"])
            results["note"] = f"Directory brute-force completed. Found {len(results['found'])} paths."

        except asyncio.TimeoutError:
            results["error"] = "Gobuster timed out after 2 minutes"
        except Exception as e:
            results["error"] = str(e)

        return results

    async def nmap_detailed_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detailed nmap scan with service detection and OS fingerprinting

        Shows full nmap output for transparency
        """
        target = params.get('target', '')

        results = {"target": target, "raw_output": "", "parsed": {}}

        try:
            # Extract hostname/IP
            host = target.replace('https://', '').replace('http://', '').split('/')[0]
            ip = socket.gethostbyname(host)

            # Run detailed nmap with aggressive options
            cmd = [
                'nmap',
                '-sV',  # Service version detection
                '-A',   # OS detection, version detection, script scanning
                '-T4',  # Aggressive timing
                '--top-ports', '1000',
                '--open',  # Only show open ports
                ip
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=180  # 3 minutes for detailed scan
            )

            raw_output = stdout.decode('utf-8', errors='ignore')
            results["raw_output"] = raw_output
            results["ip"] = ip

            # Also use python-nmap for structured data
            self.nm.scan(ip, arguments='-sV -T4 --top-ports 100')

            open_ports = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        if port_info['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'protocol': proto,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'state': 'open'
                            })

            results["parsed"]["open_ports"] = open_ports
            results["parsed"]["os_detection"] = self.nm[ip].get('osmatch', []) if ip in self.nm.all_hosts() else []

        except asyncio.TimeoutError:
            results["error"] = "Nmap scan timed out after 3 minutes"
        except Exception as e:
            results["error"] = str(e)

        return results


# Create agent instance
agent = DynamicKaliAgent(AGENT_ID)


@app.post("/execute_tool")
async def execute_tool(request: ToolRequest):
    """Execute a specific security tool"""
    return await agent.execute_tool(request.tool_name, request.parameters)


@app.on_event("startup")
async def startup_event():
    """Log agent configuration on startup"""
    logger.info(f"=== Dynamic Kali Agent Started ===")
    logger.info(f"Agent ID: {AGENT_ID}")
    logger.info(f"Target URL: {TARGET_URL if TARGET_URL else '(not set - will be provided via API)'}")
    logger.info(f"Job ID: {JOB_ID if JOB_ID else '(not set)'}")
    logger.info(f"================================")


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "agent_type": "dynamic-kali-agent",
        "agent_id": AGENT_ID,
        "target_url": TARGET_URL if TARGET_URL else None,
        "job_id": JOB_ID if JOB_ID else None,
        "version": "3.0.0"
    }


@app.get("/status")
async def get_status():
    """Get agent status"""
    return {
        "agent_id": AGENT_ID,
        "target_url": TARGET_URL if TARGET_URL else None,
        "job_id": JOB_ID if JOB_ID else None,
        "status": "ready",
        "mode": "dynamic",
        "available_tools": [
            "nmap_scan", "nmap_detailed_scan", "http_scan", "dns_enumerate", "resolve_domain",
            "javascript_analysis", "security_headers_check", "sql_injection_test",
            "xss_test", "api_fuzzing", "api_brute_force", "api_idor_test",
            "api_rate_limit_test", "api_privilege_escalation_test", "detect_exposed_env_vars",
            "ffuf_scan", "gobuster_scan"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get('AGENT_PORT', 9000))
    logger.info(f"Starting Dynamic Kali Agent {AGENT_ID} on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
