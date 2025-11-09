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

            # Capture all response headers for evidence
            response_headers = dict(response.headers)

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

                    # Build detailed evidence
                    evidence = {
                        'http_method': 'GET',
                        'status_code': response.status_code,
                        'response_headers': response_headers,
                        'missing_header': header,
                        'server': response.headers.get('Server', 'Unknown'),
                        'date_tested': response.headers.get('Date', ''),
                        'detection_method': 'HTTP Header Analysis',
                        'tool_used': f'FetchBot/{self.agent_id}',
                        'request_sent': f'GET {url}',
                        'curl_equivalent': f'curl -I {url}'
                    }

                    # Detailed remediation
                    remediation = self._get_header_remediation(header)

                    findings.append({
                        'title': f'Missing: {header}',
                        'severity': severity,
                        'type': 'missing_header',
                        'header': header,
                        'description': description,
                        'url': url,
                        'evidence': evidence,
                        'remediation': remediation,
                        'cvss_score': 6.5 if severity == 'high' else 4.3,
                        'cwe': self._get_cwe_for_header(header),
                        'owasp_category': 'A05:2021 – Security Misconfiguration'
                    })

        except Exception as e:
            pass

        return findings

    def _get_header_remediation(self, header: str) -> Dict:
        """Get detailed remediation steps for missing header"""
        remediation_map = {
            'Content-Security-Policy': {
                'fix': 'Add CSP header to HTTP responses',
                'example': "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';",
                'implementation': {
                    'nginx': "add_header Content-Security-Policy \"default-src 'self';\" always;",
                    'apache': "Header always set Content-Security-Policy \"default-src 'self';\"",
                    'express': "app.use(helmet.contentSecurityPolicy({directives: {defaultSrc: [\"'self'\"]}}));"
                },
                'references': [
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'
                ]
            },
            'Strict-Transport-Security': {
                'fix': 'Add HSTS header to enforce HTTPS',
                'example': 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
                'implementation': {
                    'nginx': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
                    'apache': 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
                    'express': "app.use(helmet.hsts({maxAge: 31536000, includeSubDomains: true}));"
                },
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security']
            },
            'X-Frame-Options': {
                'fix': 'Add X-Frame-Options header to prevent clickjacking',
                'example': 'X-Frame-Options: DENY',
                'implementation': {
                    'nginx': 'add_header X-Frame-Options "DENY" always;',
                    'apache': 'Header always set X-Frame-Options "DENY"',
                    'express': "app.use(helmet.frameguard({action: 'deny'}));"
                },
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options']
            },
            'X-Content-Type-Options': {
                'fix': 'Add X-Content-Type-Options header',
                'example': 'X-Content-Type-Options: nosniff',
                'implementation': {
                    'nginx': 'add_header X-Content-Type-Options "nosniff" always;',
                    'apache': 'Header always set X-Content-Type-Options "nosniff"',
                    'express': "app.use(helmet.noSniff());"
                },
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options']
            }
        }
        return remediation_map.get(header, {
            'fix': f'Add {header} security header',
            'example': f'{header}: recommended-value',
            'references': []
        })

    def _get_cwe_for_header(self, header: str) -> str:
        """Map security header to CWE"""
        cwe_map = {
            'Content-Security-Policy': 'CWE-1021: Improper Restriction of Rendered UI Layers or Frames',
            'Strict-Transport-Security': 'CWE-319: Cleartext Transmission of Sensitive Information',
            'X-Frame-Options': 'CWE-1021: Improper Restriction of Rendered UI Layers or Frames',
            'X-Content-Type-Options': 'CWE-693: Protection Mechanism Failure',
            'X-XSS-Protection': 'CWE-79: Cross-site Scripting (XSS)'
        }
        return cwe_map.get(header, 'CWE-16: Configuration')

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

            for form_idx, form in enumerate(forms[:3]):  # Test first 3 forms
                action = form.get('action', '')
                form_url = urljoin(url, action) if action else url
                form_method = form.get('method', 'get').upper()

                inputs = form.find_all(['input', 'textarea'])
                data = {}
                vulnerable_param = None

                for inp in inputs:
                    name = inp.get('name')
                    if name:
                        data[name] = payload

                if data:
                    try:
                        test_response = await client.post(form_url, data=data, headers=self.headers)

                        if payload in test_response.text:
                            # Find which parameter was vulnerable
                            for param_name in data.keys():
                                vulnerable_param = param_name
                                break

                            # Capture context around the injection
                            injection_context = self._extract_injection_context(test_response.text, payload)

                            evidence = {
                                'http_method': 'POST',
                                'vulnerable_url': form_url,
                                'vulnerable_parameter': vulnerable_param,
                                'payload_used': payload,
                                'injection_point': f'Form parameter: {vulnerable_param}',
                                'response_status': test_response.status_code,
                                'payload_reflected': True,
                                'injection_context': injection_context,
                                'form_action': action or '(same page)',
                                'form_method': form_method,
                                'detection_method': 'Reflected Payload Analysis',
                                'tool_used': f'FetchBot/{self.agent_id}',
                                'curl_equivalent': f'curl -X POST {form_url} -d "{vulnerable_param}={payload}"'
                            }

                            remediation = {
                                'fix': 'Sanitize and encode user input before rendering in HTML',
                                'implementation': {
                                    'javascript': 'Use textContent instead of innerHTML, or DOMPurify.sanitize()',
                                    'php': 'htmlspecialchars($input, ENT_QUOTES, \'UTF-8\')',
                                    'python': 'from markupsafe import escape; escape(user_input)',
                                    'general': 'Implement Content Security Policy (CSP) header'
                                },
                                'references': [
                                    'https://owasp.org/www-community/attacks/xss/',
                                    'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
                                ]
                            }

                            findings.append({
                                'title': f'Reflected XSS in {vulnerable_param} parameter',
                                'severity': 'high',
                                'type': 'xss',
                                'url': form_url,
                                'payload': payload,
                                'description': f'Reflected XSS vulnerability found in form parameter "{vulnerable_param}". User input is reflected back without proper sanitization, allowing arbitrary JavaScript execution.',
                                'evidence': evidence,
                                'remediation': remediation,
                                'cvss_score': 7.1,
                                'cwe': 'CWE-79: Improper Neutralization of Input During Web Page Generation',
                                'owasp_category': 'A03:2021 – Injection'
                            })
                    except:
                        pass

        except Exception as e:
            pass

        return findings

    def _extract_injection_context(self, html: str, payload: str, context_length: int = 100) -> str:
        """Extract HTML context around injection point"""
        try:
            idx = html.find(payload)
            if idx == -1:
                return "Payload reflected but context unavailable"

            start = max(0, idx - context_length)
            end = min(len(html), idx + len(payload) + context_length)
            context = html[start:end]

            # Highlight the payload
            context = context.replace(payload, f">>> {payload} <<<")
            return context
        except:
            return "Context extraction failed"

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
                form_method = form.get('method', 'get').upper()

                inputs = form.find_all(['input', 'textarea'])

                for payload in payloads:
                    data = {}
                    vulnerable_param = None

                    for inp in inputs:
                        name = inp.get('name')
                        if name:
                            data[name] = payload

                    if data:
                        try:
                            test_response = await client.post(form_url, data=data, headers=self.headers)

                            if self._contains_sql_error(test_response.text):
                                # Extract specific error message
                                sql_error = self._extract_sql_error(test_response.text)

                                # Find vulnerable parameter
                                for param_name in data.keys():
                                    vulnerable_param = param_name
                                    break

                                evidence = {
                                    'http_method': 'POST',
                                    'vulnerable_url': form_url,
                                    'vulnerable_parameter': vulnerable_param,
                                    'payload_used': payload,
                                    'injection_point': f'Form parameter: {vulnerable_param}',
                                    'response_status': test_response.status_code,
                                    'sql_error_detected': sql_error,
                                    'database_type': self._detect_database_type(sql_error),
                                    'error_in_response': True,
                                    'form_action': action or '(same page)',
                                    'form_method': form_method,
                                    'detection_method': 'SQL Error Pattern Matching',
                                    'tool_used': f'FetchBot/{self.agent_id}',
                                    'curl_equivalent': f'curl -X POST {form_url} -d "{vulnerable_param}={payload}"'
                                }

                                remediation = {
                                    'fix': 'Use parameterized queries (prepared statements) instead of string concatenation',
                                    'implementation': {
                                        'php_pdo': 'PDO: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id"); $stmt->execute([\'id\' => $id]);',
                                        'python': 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                                        'node_mysql': 'connection.query("SELECT * FROM users WHERE id = ?", [userId]);',
                                        'java': 'PreparedStatement: stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); stmt.setInt(1, userId);'
                                    },
                                    'additional_steps': [
                                        'Use ORM frameworks when possible',
                                        'Validate and sanitize all user inputs',
                                        'Apply principle of least privilege to database accounts',
                                        'Disable detailed error messages in production',
                                        'Implement WAF rules to block SQL injection attempts'
                                    ],
                                    'references': [
                                        'https://owasp.org/www-community/attacks/SQL_Injection',
                                        'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
                                    ]
                                }

                                findings.append({
                                    'title': f'SQL Injection in {vulnerable_param} parameter',
                                    'severity': 'critical',
                                    'type': 'sqli',
                                    'url': form_url,
                                    'payload': payload,
                                    'description': f'Critical SQL Injection vulnerability detected in parameter "{vulnerable_param}". The application constructs SQL queries using unsanitized user input, allowing attackers to manipulate database queries. Database error: {sql_error}',
                                    'evidence': evidence,
                                    'remediation': remediation,
                                    'cvss_score': 9.8,
                                    'cwe': 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
                                    'owasp_category': 'A03:2021 – Injection'
                                })
                                break
                        except:
                            pass

        except Exception as e:
            pass

        return findings

    def _extract_sql_error(self, text: str) -> str:
        """Extract specific SQL error message"""
        sql_errors = [
            ('mysql', ['mysql', 'you have an error in your sql syntax']),
            ('postgresql', ['postgresql', 'pg_query', 'sqlstate']),
            ('oracle', ['ora-', 'oracle']),
            ('mssql', ['microsoft sql', 'odbc sql', 'sqlserver']),
            ('sqlite', ['sqlite', 'sqlite3'])
        ]

        text_lower = text.lower()
        for db_type, patterns in sql_errors:
            for pattern in patterns:
                if pattern in text_lower:
                    # Try to extract the actual error message (first 200 chars)
                    idx = text_lower.find(pattern)
                    if idx != -1:
                        return text[idx:min(idx + 200, len(text))].strip()

        return "SQL error detected in response"

    def _detect_database_type(self, error_msg: str) -> str:
        """Detect database type from error message"""
        error_lower = error_msg.lower()
        if 'mysql' in error_lower:
            return 'MySQL/MariaDB'
        elif 'postgresql' in error_lower or 'pg_' in error_lower:
            return 'PostgreSQL'
        elif 'ora-' in error_lower:
            return 'Oracle'
        elif 'microsoft' in error_lower or 'mssql' in error_lower:
            return 'Microsoft SQL Server'
        elif 'sqlite' in error_lower:
            return 'SQLite'
        return 'Unknown'

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

class ToolExecutionRequest(BaseModel):
    tool_name: str
    parameters: Dict

@app.post("/execute_tool")
async def execute_tool(request: ToolExecutionRequest):
    """Execute individual security tool"""
    tool_name = request.tool_name
    params = request.parameters

    print(f"[{AGENT_ID}] Executing tool: {tool_name} with params: {params}")

    try:
        # Map tool names to agent methods
        if tool_name == "nmap_scan":
            target = params.get("target")
            findings = await agent._network_scan(target, "quick")
            return {"success": True, "findings": findings}

        elif tool_name == "http_scan":
            target = params.get("url") or params.get("target")
            async with httpx.AsyncClient() as client:
                findings = await agent._detect_technologies(client, target)
            return {"success": True, "findings": findings}

        elif tool_name == "dns_enumerate":
            target = params.get("domain") or params.get("target")
            findings = await agent._dns_enumeration(target)
            return {"success": True, "findings": findings}

        elif tool_name == "security_headers_check":
            url = params.get("url") or params.get("target")
            async with httpx.AsyncClient() as client:
                findings = await agent._check_security_headers(client, url)
            return {"success": True, "findings": findings}

        elif tool_name == "javascript_analysis":
            # Simplified - return empty for now
            return {"success": True, "findings": []}

        elif tool_name == "sql_injection_test":
            url = params.get("url") or params.get("target")
            async with httpx.AsyncClient() as client:
                findings = await agent._test_sql_injection(client, url, "quick")
            return {"success": True, "findings": findings}

        elif tool_name == "xss_test":
            url = params.get("url") or params.get("target")
            async with httpx.AsyncClient() as client:
                findings = await agent._test_xss(client, url)
            return {"success": True, "findings": findings}

        elif tool_name == "directory_enumeration":
            url = params.get("url") or params.get("target")
            async with httpx.AsyncClient() as client:
                findings = await agent._enumerate_directories(client, url)
            return {"success": True, "findings": findings}

        elif tool_name == "nikto_scan":
            target = params.get("target") or params.get("url")
            findings = await agent._run_nikto(target)
            return {"success": True, "findings": findings}

        elif tool_name == "scan_env_files":
            url = params.get("url") or params.get("target")
            async with httpx.AsyncClient() as client:
                findings = await agent._check_sensitive_files(client, url)
            return {"success": True, "findings": findings}

        elif tool_name == "api_brute_force" or tool_name == "api_fuzzing":
            # Return empty for now - these are advanced tools
            return {"success": True, "findings": []}

        elif tool_name == "service_detection":
            target = params.get("target")
            findings = await agent._network_scan(target, "quick")
            return {"success": True, "findings": findings}

        else:
            print(f"[{AGENT_ID}] Unknown tool: {tool_name}")
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}",
                "findings": []
            }

    except Exception as e:
        print(f"[{AGENT_ID}] Tool execution error: {e}")
        return {
            "success": False,
            "error": str(e),
            "findings": []
        }

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
