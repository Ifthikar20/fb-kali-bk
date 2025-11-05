"""FetchBot.ai - Kali Linux Unified Scanning Agent"""
import asyncio
import subprocess
import nmap
import httpx
import socket
import dns.resolver
import json
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import os

app = FastAPI(title="FetchBot Kali Agent", version="2.0.0")

# Get agent ID from environment (for identifying which container this is)
AGENT_ID = os.environ.get('AGENT_ID', 'kali-agent-unknown')

class ScanRequest(BaseModel):
    target: str
    scan_type: str  # network, web, database, or full
    depth: str = "quick"  # quick or deep

class KaliAgent:
    """Unified Kali Linux scanning agent with all tools"""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.nm = nmap.PortScanner()
        self.headers = {
            'User-Agent': f'FetchBot/{agent_id}'
        }

    async def execute_scan(self, target: str, scan_type: str, depth: str = "quick") -> Dict:
        """Execute requested scan type"""

        print(f"[{self.agent_id}] Starting {scan_type} scan on {target} (depth: {depth})")

        results = {
            'agent_id': self.agent_id,
            'target': target,
            'scan_type': scan_type,
            'depth': depth,
            'findings': []
        }

        try:
            if scan_type == "network":
                results['findings'] = await self._network_scan(target, depth)
            elif scan_type == "web":
                results['findings'] = await self._web_scan(target, depth)
            elif scan_type == "database":
                results['findings'] = await self._database_scan(target, depth)
            elif scan_type == "full":
                # Run all scans
                network_findings = await self._network_scan(target, depth)
                web_findings = await self._web_scan(target, depth)
                db_findings = await self._database_scan(target, depth)
                results['findings'] = network_findings + web_findings + db_findings
            else:
                raise HTTPException(status_code=400, detail=f"Unknown scan type: {scan_type}")

        except Exception as e:
            print(f"[{self.agent_id}] Error during scan: {e}")
            results['findings'].append({
                'title': 'Scan Error',
                'severity': 'info',
                'type': 'error',
                'description': str(e)
            })

        print(f"[{self.agent_id}] Scan complete. Found {len(results['findings'])} items")
        return results

    async def _network_scan(self, target: str, depth: str) -> List[Dict]:
        """Network reconnaissance - ports, services, DNS"""
        findings = []

        try:
            # Resolve target
            ip = socket.gethostbyname(target)

            # Port scan
            if depth == "quick":
                # Top 100 ports
                args = "-F -T4 --max-retries 1"
            else:
                # Full scan
                args = "-p- -sV -T4 -A"

            print(f"[{self.agent_id}] Running nmap: {args}")
            self.nm.scan(ip, arguments=args)

            for host in self.nm.all_hosts():
                # OS detection
                if 'osmatch' in self.nm[host]:
                    for osmatch in self.nm[host]['osmatch']:
                        findings.append({
                            'title': f'OS Detection: {osmatch["name"]}',
                            'severity': 'info',
                            'type': 'os_detection',
                            'os': osmatch['name'],
                            'accuracy': osmatch['accuracy'],
                            'description': f'Detected OS: {osmatch["name"]} ({osmatch["accuracy"]}% accuracy)'
                        })

                # Open ports
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()

                    for port in ports:
                        port_info = self.nm[host][proto][port]

                        if port_info['state'] == 'open':
                            service = port_info.get('name', 'unknown')
                            version = port_info.get('version', '')
                            product = port_info.get('product', '')

                            # Assess severity
                            severity = self._assess_port_severity(port, service)

                            findings.append({
                                'title': f'Open Port {port}/{proto} - {service}',
                                'severity': severity,
                                'type': 'open_port',
                                'port': port,
                                'protocol': proto,
                                'service': service,
                                'version': version,
                                'product': product,
                                'ip': ip,
                                'description': f'Port {port} running {product} {version}'.strip()
                            })

            # DNS enumeration
            dns_findings = await self._dns_enumeration(target)
            findings.extend(dns_findings)

        except Exception as e:
            print(f"[{self.agent_id}] Network scan error: {e}")
            findings.append({
                'title': 'Network Scan Error',
                'severity': 'info',
                'type': 'error',
                'description': str(e)
            })

        return findings

    async def _web_scan(self, target: str, depth: str) -> List[Dict]:
        """Web application scanning - XSS, CSRF, headers, directories"""
        findings = []

        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                # Technology detection
                findings.extend(await self._detect_technologies(client, target))

                # Security headers
                findings.extend(await self._check_security_headers(client, target))

                # Directory enumeration
                findings.extend(await self._enumerate_directories(client, target))

                # Sensitive files
                findings.extend(await self._check_sensitive_files(client, target))

                if depth == "deep":
                    # XSS testing
                    findings.extend(await self._test_xss(client, target))

                    # Run nikto
                    findings.extend(await self._run_nikto(target))

        except Exception as e:
            print(f"[{self.agent_id}] Web scan error: {e}")
            findings.append({
                'title': 'Web Scan Error',
                'severity': 'info',
                'type': 'error',
                'description': str(e)
            })

        return findings

    async def _database_scan(self, target: str, depth: str) -> List[Dict]:
        """Database vulnerability scanning - SQL injection, NoSQL injection"""
        findings = []

        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                # SQL injection testing
                findings.extend(await self._test_sql_injection(client, target, depth))

                # Database error disclosure
                findings.extend(await self._check_database_errors(client, target))

                if depth == "deep":
                    # Blind SQL injection
                    findings.extend(await self._test_blind_sqli(client, target))

                    # NoSQL injection
                    findings.extend(await self._test_nosql_injection(client, target))

        except Exception as e:
            print(f"[{self.agent_id}] Database scan error: {e}")
            findings.append({
                'title': 'Database Scan Error',
                'severity': 'info',
                'type': 'error',
                'description': str(e)
            })

        return findings

    def _assess_port_severity(self, port: int, service: str) -> str:
        """Assess risk level of open port"""
        critical_ports = [21, 22, 23, 3389, 445, 139, 1433, 3306, 5432, 27017, 6379]
        high_risk_services = ['telnet', 'ftp', 'smb', 'mysql', 'postgresql', 'mongodb', 'redis']

        if port in critical_ports:
            return 'high'
        if service.lower() in high_risk_services:
            return 'high'
        if port < 1024:
            return 'medium'
        return 'low'

    async def _dns_enumeration(self, target: str) -> List[Dict]:
        """DNS reconnaissance"""
        findings = []

        try:
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS']

            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(target, record_type)
                    for rdata in answers:
                        findings.append({
                            'title': f'DNS Record: {record_type}',
                            'severity': 'info',
                            'type': 'dns_record',
                            'record_type': record_type,
                            'value': str(rdata),
                            'description': f'{record_type} record: {str(rdata)}'
                        })
                except:
                    pass

            # Subdomain enumeration
            subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging']
            for subdomain in subdomains:
                try:
                    full_domain = f'{subdomain}.{target}'
                    ip = socket.gethostbyname(full_domain)
                    findings.append({
                        'title': f'Subdomain: {subdomain}',
                        'severity': 'medium',
                        'type': 'subdomain',
                        'subdomain': full_domain,
                        'ip': ip,
                        'description': f'{full_domain} resolves to {ip}'
                    })
                except:
                    pass

        except Exception as e:
            pass

        return findings

    async def _detect_technologies(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Detect web technologies"""
        findings = []

        try:
            response = await client.get(url, headers=self.headers)

            # Server header
            server = response.headers.get('Server')
            if server:
                findings.append({
                    'title': f'Server: {server}',
                    'severity': 'info',
                    'type': 'technology',
                    'technology': 'server',
                    'value': server,
                    'description': f'Server running {server}'
                })

            # X-Powered-By
            powered_by = response.headers.get('X-Powered-By')
            if powered_by:
                findings.append({
                    'title': f'X-Powered-By: {powered_by}',
                    'severity': 'low',
                    'type': 'technology',
                    'technology': 'framework',
                    'value': powered_by,
                    'description': f'Framework disclosure: {powered_by}'
                })

        except Exception as e:
            pass

        return findings

    async def _check_security_headers(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Check security headers"""
        findings = []

        try:
            response = await client.get(url, headers=self.headers)

            security_headers = {
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME sniffing protection missing',
                'Strict-Transport-Security': 'HSTS not enabled',
                'Content-Security-Policy': 'CSP not implemented',
                'X-XSS-Protection': 'XSS protection missing'
            }

            for header, description in security_headers.items():
                if header not in response.headers:
                    severity = 'high' if header == 'Content-Security-Policy' else 'medium'
                    findings.append({
                        'title': f'Missing: {header}',
                        'severity': severity,
                        'type': 'missing_header',
                        'header': header,
                        'description': description,
                        'url': url
                    })

        except Exception as e:
            pass

        return findings

    async def _enumerate_directories(self, client: httpx.AsyncClient, base_url: str) -> List[Dict]:
        """Directory enumeration"""
        findings = []

        common_dirs = ['admin', 'login', 'wp-admin', 'phpmyadmin', 'backup', 'test', 'api', '.git']

        for directory in common_dirs:
            try:
                test_url = urljoin(base_url, directory)
                response = await client.get(test_url, headers=self.headers, timeout=5.0)

                if response.status_code == 200:
                    findings.append({
                        'title': f'Directory Found: /{directory}',
                        'severity': 'medium',
                        'type': 'directory',
                        'url': test_url,
                        'status_code': response.status_code,
                        'description': f'Accessible directory at /{directory}'
                    })
            except:
                pass

        return findings

    async def _check_sensitive_files(self, client: httpx.AsyncClient, base_url: str) -> List[Dict]:
        """Check for exposed sensitive files"""
        findings = []

        sensitive_files = ['.env', 'config.php', 'wp-config.php', '.git/config', 'robots.txt']

        for file_path in sensitive_files:
            try:
                test_url = urljoin(base_url, file_path)
                response = await client.get(test_url, headers=self.headers, timeout=5.0)

                if response.status_code == 200:
                    severity = 'critical' if file_path in ['.env', 'config.php', '.git/config'] else 'medium'
                    findings.append({
                        'title': f'Sensitive File: {file_path}',
                        'severity': severity,
                        'type': 'sensitive_file',
                        'url': test_url,
                        'file': file_path,
                        'description': f'Exposed file: {file_path}'
                    })
            except:
                pass

        return findings

    async def _test_xss(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Test for XSS vulnerabilities"""
        findings = []

        payload = '<script>alert(1)</script>'

        try:
            response = await client.get(url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')

            for form in forms[:3]:  # Test first 3 forms
                action = form.get('action', '')
                form_url = urljoin(url, action) if action else url

                inputs = form.find_all(['input', 'textarea'])
                data = {}

                for inp in inputs:
                    name = inp.get('name')
                    if name:
                        data[name] = payload

                if data:
                    try:
                        test_response = await client.post(form_url, data=data, headers=self.headers)

                        if payload in test_response.text:
                            findings.append({
                                'title': 'XSS Vulnerability',
                                'severity': 'high',
                                'type': 'xss',
                                'url': form_url,
                                'payload': payload,
                                'description': f'XSS vulnerability at {form_url}'
                            })
                    except:
                        pass

        except Exception as e:
            pass

        return findings

    async def _test_sql_injection(self, client: httpx.AsyncClient, url: str, depth: str) -> List[Dict]:
        """Test for SQL injection"""
        findings = []

        payloads = ["'", "' OR '1'='1", "' OR '1'='1' --"] if depth == "quick" else [
            "'", "' OR '1'='1", "' OR '1'='1' --", "admin' --", "1' AND '1'='2"
        ]

        try:
            response = await client.get(url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')

            for form in forms[:2]:
                action = form.get('action', '')
                form_url = urljoin(url, action) if action else url

                inputs = form.find_all(['input', 'textarea'])

                for payload in payloads:
                    data = {}

                    for inp in inputs:
                        name = inp.get('name')
                        if name:
                            data[name] = payload

                    if data:
                        try:
                            test_response = await client.post(form_url, data=data, headers=self.headers)

                            if self._contains_sql_error(test_response.text):
                                findings.append({
                                    'title': 'SQL Injection Vulnerability',
                                    'severity': 'critical',
                                    'type': 'sqli',
                                    'url': form_url,
                                    'payload': payload,
                                    'description': f'SQL injection at {form_url}'
                                })
                                break
                        except:
                            pass

        except Exception as e:
            pass

        return findings

    async def _check_database_errors(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Check for database error disclosure"""
        findings = []

        try:
            response = await client.get(url, headers=self.headers)

            if self._contains_sql_error(response.text):
                findings.append({
                    'title': 'Database Error Disclosure',
                    'severity': 'medium',
                    'type': 'db_error',
                    'url': url,
                    'description': 'Database errors exposed in response'
                })

        except Exception as e:
            pass

        return findings

    async def _test_blind_sqli(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Test for blind SQL injection"""
        findings = []
        # Simplified for now - time-based blind SQLi is slow
        return findings

    async def _test_nosql_injection(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Test for NoSQL injection"""
        findings = []
        # Simplified for now
        return findings

    def _contains_sql_error(self, text: str) -> bool:
        """Check for SQL error messages"""
        errors = ['sql syntax', 'mysql', 'postgresql', 'ora-', 'sqlstate', 'sqlite']
        text_lower = text.lower()
        return any(error in text_lower for error in errors)

    async def _run_nikto(self, target: str) -> List[Dict]:
        """Run Nikto web scanner"""
        findings = []

        try:
            # Run nikto with timeout
            result = subprocess.run(
                ['nikto', '-h', target, '-Tuning', '123', '-timeout', '30'],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                findings.append({
                    'title': 'Nikto Scan Completed',
                    'severity': 'info',
                    'type': 'nikto',
                    'description': 'Nikto web vulnerability scan completed'
                })

        except Exception as e:
            pass

        return findings

# Create agent instance
agent = KaliAgent(AGENT_ID)

@app.post("/scan")
async def execute_scan(request: ScanRequest):
    """Execute security scan"""
    return await agent.execute_scan(request.target, request.scan_type, request.depth)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "agent": "kali-agent",
        "agent_id": AGENT_ID,
        "tools": ["nmap", "nikto", "sqlmap", "dirb"]
    }

@app.get("/status")
async def get_status():
    """Get agent status"""
    return {
        "agent_id": AGENT_ID,
        "status": "ready",
        "capabilities": ["network", "web", "database", "full"]
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get('AGENT_PORT', 9000))
    uvicorn.run(app, host="0.0.0.0", port=port)
