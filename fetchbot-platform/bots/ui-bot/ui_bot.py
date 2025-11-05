"""UI Bot - Web Application Scanning and XSS/CSRF Detection"""
import asyncio
import subprocess
import json
import re
from typing import List, Dict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

app = FastAPI(title="UI Bot", version="1.0.0")

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"  # quick, full, deep

class WebScanner:
    def __init__(self):
        self.headers = {
            'User-Agent': 'FetchBot/1.0 Security Scanner'
        }
        self.visited_urls = set()
        self.forms_tested = set()

    async def quick_scan(self, target: str) -> Dict:
        """Quick web vulnerability scan"""
        findings = []

        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                # Technology detection
                tech_findings = await self._detect_technologies(client, target)
                findings.extend(tech_findings)

                # Security headers check
                header_findings = await self._check_security_headers(client, target)
                findings.extend(header_findings)

                # Basic XSS testing on main page
                xss_findings = await self._test_xss(client, target)
                findings.extend(xss_findings)

                # HTTPS/SSL check
                ssl_findings = await self._check_ssl(target)
                findings.extend(ssl_findings)

                # Directory enumeration
                dir_findings = await self._enumerate_directories(client, target)
                findings.extend(dir_findings)

        except Exception as e:
            findings.append({
                'title': 'Web Scan Error',
                'severity': 'info',
                'type': 'error',
                'description': str(e)
            })

        return {
            'scan_type': 'quick',
            'target': target,
            'findings': findings
        }

    async def full_scan(self, target: str) -> Dict:
        """Full web vulnerability scan with crawling"""
        findings = []

        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                # Technology detection
                tech_findings = await self._detect_technologies(client, target)
                findings.extend(tech_findings)

                # Security headers
                header_findings = await self._check_security_headers(client, target)
                findings.extend(header_findings)

                # Crawl site and find forms
                urls, forms = await self._crawl_site(client, target, max_depth=2)

                # Test each form for XSS
                for form_info in forms:
                    xss_findings = await self._test_form_xss(client, form_info)
                    findings.extend(xss_findings)

                # CSRF token check
                csrf_findings = await self._check_csrf(forms)
                findings.extend(csrf_findings)

                # Directory enumeration
                dir_findings = await self._enumerate_directories(client, target)
                findings.extend(dir_findings)

                # Check for sensitive files
                sensitive_findings = await self._check_sensitive_files(client, target)
                findings.extend(sensitive_findings)

                # Nikto scan (if available)
                nikto_findings = await self._run_nikto(target)
                findings.extend(nikto_findings)

        except Exception as e:
            findings.append({
                'title': 'Full Web Scan Error',
                'severity': 'info',
                'type': 'error',
                'description': str(e)
            })

        return {
            'scan_type': 'full',
            'target': target,
            'findings': findings
        }

    async def _detect_technologies(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Detect web technologies"""
        findings = []

        try:
            response = await client.get(url, headers=self.headers)

            # Server header
            server = response.headers.get('Server', 'Unknown')
            if server != 'Unknown':
                findings.append({
                    'title': f'Server Technology: {server}',
                    'severity': 'info',
                    'type': 'technology',
                    'technology': 'server',
                    'value': server,
                    'description': f'Server is running {server}'
                })

            # X-Powered-By
            powered_by = response.headers.get('X-Powered-By')
            if powered_by:
                findings.append({
                    'title': f'Technology Disclosure: {powered_by}',
                    'severity': 'low',
                    'type': 'technology',
                    'technology': 'framework',
                    'value': powered_by,
                    'description': f'X-Powered-By header reveals: {powered_by}'
                })

            # Framework detection from HTML
            soup = BeautifulSoup(response.text, 'html.parser')

            # WordPress detection
            if soup.find('meta', {'name': 'generator', 'content': re.compile('WordPress', re.I)}):
                findings.append({
                    'title': 'WordPress Detected',
                    'severity': 'medium',
                    'type': 'cms',
                    'cms': 'WordPress',
                    'description': 'Site is running WordPress CMS'
                })

            # jQuery version
            jquery_scripts = soup.find_all('script', src=re.compile('jquery', re.I))
            for script in jquery_scripts:
                src = script.get('src', '')
                version_match = re.search(r'jquery[.-](\d+\.\d+\.\d+)', src, re.I)
                if version_match:
                    version = version_match.group(1)
                    findings.append({
                        'title': f'jQuery Version: {version}',
                        'severity': 'info',
                        'type': 'library',
                        'library': 'jQuery',
                        'version': version,
                        'description': f'Using jQuery version {version}'
                    })

        except Exception as e:
            pass

        return findings

    async def _check_security_headers(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Check for security headers"""
        findings = []

        try:
            response = await client.get(url, headers=self.headers)

            # Missing security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME sniffing protection missing',
                'Strict-Transport-Security': 'HSTS not enabled',
                'Content-Security-Policy': 'CSP not implemented',
                'X-XSS-Protection': 'XSS protection header missing'
            }

            for header, description in security_headers.items():
                if header not in response.headers:
                    severity = 'high' if header == 'Content-Security-Policy' else 'medium'
                    findings.append({
                        'title': f'Missing Security Header: {header}',
                        'severity': severity,
                        'type': 'missing_header',
                        'header': header,
                        'description': description,
                        'url': url
                    })

        except Exception as e:
            pass

        return findings

    async def _test_xss(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Test for XSS vulnerabilities"""
        findings = []

        # Common XSS payloads
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)'
        ]

        try:
            # Get the page
            response = await client.get(url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find input forms
            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()

                # Get form action URL
                form_url = urljoin(url, action) if action else url

                # Find all input fields
                inputs = form.find_all(['input', 'textarea'])

                for payload in xss_payloads[:2]:  # Test first 2 payloads
                    data = {}

                    for inp in inputs:
                        name = inp.get('name')
                        if name:
                            inp_type = inp.get('type', 'text')
                            if inp_type in ['text', 'search', 'email']:
                                data[name] = payload
                            else:
                                data[name] = 'test'

                    if data:
                        try:
                            if method == 'post':
                                test_response = await client.post(form_url, data=data, headers=self.headers)
                            else:
                                test_response = await client.get(form_url, params=data, headers=self.headers)

                            # Check if payload is reflected
                            if payload in test_response.text:
                                findings.append({
                                    'title': 'Potential XSS Vulnerability',
                                    'severity': 'high',
                                    'type': 'xss',
                                    'url': form_url,
                                    'method': method.upper(),
                                    'payload': payload,
                                    'description': f'XSS payload reflected in response at {form_url}',
                                    'poc': f'{method.upper()} {form_url} with payload: {payload}'
                                })
                                break  # Found vulnerability, no need to test other payloads
                        except:
                            pass

        except Exception as e:
            pass

        return findings

    async def _check_ssl(self, url: str) -> List[Dict]:
        """Check SSL/TLS configuration"""
        findings = []

        if url.startswith('http://'):
            findings.append({
                'title': 'No HTTPS Encryption',
                'severity': 'critical',
                'type': 'ssl',
                'url': url,
                'description': 'Site is not using HTTPS encryption'
            })

        return findings

    async def _enumerate_directories(self, client: httpx.AsyncClient, base_url: str) -> List[Dict]:
        """Enumerate common directories"""
        findings = []

        common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
            'backup', 'backups', 'test', 'dev', 'api', 'uploads', '.git',
            'config', 'database', 'db'
        ]

        for directory in common_dirs:
            test_url = urljoin(base_url, directory)

            try:
                response = await client.get(test_url, headers=self.headers, timeout=5.0)

                if response.status_code == 200:
                    findings.append({
                        'title': f'Directory Found: /{directory}',
                        'severity': 'medium',
                        'type': 'directory',
                        'url': test_url,
                        'status_code': response.status_code,
                        'description': f'Accessible directory found at /{directory}'
                    })
                elif response.status_code == 401:
                    findings.append({
                        'title': f'Protected Directory: /{directory}',
                        'severity': 'low',
                        'type': 'directory',
                        'url': test_url,
                        'status_code': response.status_code,
                        'description': f'Password-protected directory at /{directory}'
                    })
            except:
                pass

        return findings

    async def _check_sensitive_files(self, client: httpx.AsyncClient, base_url: str) -> List[Dict]:
        """Check for sensitive files"""
        findings = []

        sensitive_files = [
            '.git/config', '.env', 'config.php', 'wp-config.php',
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'phpinfo.php', 'readme.md', 'README.md'
        ]

        for file_path in sensitive_files:
            test_url = urljoin(base_url, file_path)

            try:
                response = await client.get(test_url, headers=self.headers, timeout=5.0)

                if response.status_code == 200:
                    severity = 'critical' if file_path in ['.env', 'config.php', '.git/config'] else 'medium'

                    findings.append({
                        'title': f'Sensitive File Exposed: {file_path}',
                        'severity': severity,
                        'type': 'sensitive_file',
                        'url': test_url,
                        'file': file_path,
                        'description': f'Sensitive file accessible at {file_path}'
                    })
            except:
                pass

        return findings

    async def _crawl_site(self, client: httpx.AsyncClient, url: str, max_depth: int = 2) -> tuple:
        """Crawl site to discover URLs and forms"""
        urls = set()
        forms = []

        try:
            response = await client.get(url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract forms
            for form in soup.find_all('form'):
                form_info = {
                    'url': url,
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }

                for inp in form.find_all(['input', 'textarea', 'select']):
                    form_info['inputs'].append({
                        'name': inp.get('name'),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', '')
                    })

                forms.append(form_info)

            # Extract links (limited crawl)
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)

                # Only crawl same domain
                if urlparse(full_url).netloc == urlparse(url).netloc:
                    urls.add(full_url)

        except Exception as e:
            pass

        return list(urls)[:20], forms  # Limit URLs for efficiency

    async def _test_form_xss(self, client: httpx.AsyncClient, form_info: Dict) -> List[Dict]:
        """Test specific form for XSS"""
        findings = []
        payload = '<script>alert(1)</script>'

        try:
            data = {}
            for inp in form_info['inputs']:
                name = inp.get('name')
                if name:
                    data[name] = payload if inp['type'] in ['text', 'search'] else 'test'

            if data:
                if form_info['method'] == 'post':
                    response = await client.post(form_info['action'], data=data, headers=self.headers)
                else:
                    response = await client.get(form_info['action'], params=data, headers=self.headers)

                if payload in response.text:
                    findings.append({
                        'title': 'XSS Vulnerability in Form',
                        'severity': 'high',
                        'type': 'xss',
                        'url': form_info['action'],
                        'method': form_info['method'].upper(),
                        'payload': payload,
                        'description': f'Form at {form_info["action"]} is vulnerable to XSS'
                    })
        except:
            pass

        return findings

    async def _check_csrf(self, forms: List[Dict]) -> List[Dict]:
        """Check for CSRF protection"""
        findings = []

        csrf_tokens = ['csrf', 'csrf_token', '_csrf', 'token', 'authenticity_token']

        for form in forms:
            has_csrf = False

            for inp in form['inputs']:
                if inp.get('name', '').lower() in csrf_tokens:
                    has_csrf = True
                    break

            if not has_csrf and form['method'] == 'post':
                findings.append({
                    'title': 'Missing CSRF Protection',
                    'severity': 'medium',
                    'type': 'csrf',
                    'url': form['action'],
                    'description': f'POST form at {form["action"]} lacks CSRF token'
                })

        return findings

    async def _run_nikto(self, target: str) -> List[Dict]:
        """Run Nikto web scanner"""
        findings = []

        try:
            # Run nikto with JSON output
            result = subprocess.run(
                ['nikto', '-h', target, '-Format', 'json', '-Tuning', '123', '-timeout', '30'],
                capture_output=True,
                text=True,
                timeout=120
            )

            # Parse nikto output (simplified)
            if result.stdout:
                findings.append({
                    'title': 'Nikto Scan Completed',
                    'severity': 'info',
                    'type': 'nikto',
                    'description': 'Nikto vulnerability scan completed'
                })

        except Exception as e:
            pass

        return findings

scanner = WebScanner()

@app.post("/scan")
async def scan_target(request: ScanRequest):
    """Execute web vulnerability scan"""

    if request.scan_type == "quick":
        results = await scanner.quick_scan(request.target)
    elif request.scan_type in ["full", "deep"]:
        results = await scanner.full_scan(request.target)
    else:
        raise HTTPException(status_code=400, detail="Invalid scan type")

    return results

@app.get("/health")
async def health_check():
    return {"status": "healthy", "bot": "ui-bot"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
