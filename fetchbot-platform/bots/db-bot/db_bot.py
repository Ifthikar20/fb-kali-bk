"""DB Bot - SQL Injection and Database Vulnerability Detection"""
import asyncio
import subprocess
import json
import re
from typing import List, Dict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

app = FastAPI(title="DB Bot", version="1.0.0")

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"  # quick, full

class DatabaseScanner:
    def __init__(self):
        self.headers = {
            'User-Agent': 'FetchBot/1.0 Security Scanner'
        }

    async def quick_scan(self, target: str) -> Dict:
        """Quick SQL injection detection"""
        findings = []

        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                # Find forms and test for SQLi
                sqli_findings = await self._test_sql_injection(client, target)
                findings.extend(sqli_findings)

                # Error-based SQLi detection
                error_findings = await self._test_error_based_sqli(client, target)
                findings.extend(error_findings)

                # Check for database errors in response
                db_error_findings = await self._check_database_errors(client, target)
                findings.extend(db_error_findings)

        except Exception as e:
            findings.append({
                'title': 'DB Scan Error',
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
        """Full SQL injection and database vulnerability scan"""
        findings = []

        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                # Get page and find all forms/parameters
                response = await client.get(target, headers=self.headers)
                soup = BeautifulSoup(response.text, 'html.parser')

                # Test forms for SQLi
                forms = soup.find_all('form')
                for form in forms:
                    form_findings = await self._test_form_sqli(client, target, form)
                    findings.extend(form_findings)

                # Test URL parameters
                parsed_url = urlparse(target)
                if parsed_url.query:
                    param_findings = await self._test_url_params_sqli(client, target)
                    findings.extend(param_findings)

                # Advanced SQLi techniques
                blind_findings = await self._test_blind_sqli(client, target)
                findings.extend(blind_findings)

                # NoSQL injection tests
                nosql_findings = await self._test_nosql_injection(client, target)
                findings.extend(nosql_findings)

                # Run sqlmap (if available)
                # sqlmap_findings = await self._run_sqlmap(target)
                # findings.extend(sqlmap_findings)

        except Exception as e:
            findings.append({
                'title': 'Full DB Scan Error',
                'severity': 'info',
                'type': 'error',
                'description': str(e)
            })

        return {
            'scan_type': 'full',
            'target': target,
            'findings': findings
        }

    async def _test_sql_injection(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Test for basic SQL injection"""
        findings = []

        # Common SQLi payloads
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2"
        ]

        try:
            response = await client.get(url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(url, action) if action else url

                inputs = form.find_all(['input', 'textarea'])

                for payload in sqli_payloads[:3]:  # Test first 3 payloads
                    data = {}

                    for inp in inputs:
                        name = inp.get('name')
                        if name:
                            inp_type = inp.get('type', 'text')
                            # Inject payload into text-based inputs
                            if inp_type in ['text', 'password', 'email', 'search']:
                                data[name] = payload
                            else:
                                data[name] = 'test'

                    if data:
                        try:
                            if method == 'post':
                                test_response = await client.post(form_url, data=data, headers=self.headers)
                            else:
                                test_response = await client.get(form_url, params=data, headers=self.headers)

                            # Check for SQL errors
                            if self._contains_sql_error(test_response.text):
                                findings.append({
                                    'title': 'SQL Injection Vulnerability',
                                    'severity': 'critical',
                                    'type': 'sqli',
                                    'url': form_url,
                                    'method': method.upper(),
                                    'payload': payload,
                                    'description': f'SQL injection vulnerability detected at {form_url}',
                                    'poc': f'{method.upper()} {form_url} with payload: {payload}'
                                })
                                break  # Found vulnerability

                            # Check for successful bypass (different content length)
                            normal_response = await client.get(url, headers=self.headers)
                            if abs(len(test_response.text) - len(normal_response.text)) > 100:
                                findings.append({
                                    'title': 'Potential SQL Injection',
                                    'severity': 'high',
                                    'type': 'sqli',
                                    'url': form_url,
                                    'method': method.upper(),
                                    'payload': payload,
                                    'description': f'Possible SQL injection - response size changed significantly',
                                    'evidence': f'Normal: {len(normal_response.text)} bytes, Test: {len(test_response.text)} bytes'
                                })

                        except:
                            pass

        except Exception as e:
            pass

        return findings

    async def _test_error_based_sqli(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Test for error-based SQL injection"""
        findings = []

        error_payloads = [
            "'",
            "\"",
            "' AND 1=1--",
            "' AND 1=2--",
            "1/0",
            "' OR '1",
        ]

        try:
            response = await client.get(url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action', '')
                form_url = urljoin(url, action) if action else url
                method = form.get('method', 'get').lower()

                inputs = form.find_all(['input', 'textarea'])

                for payload in error_payloads[:3]:
                    data = {}

                    for inp in inputs:
                        name = inp.get('name')
                        if name:
                            inp_type = inp.get('type', 'text')
                            if inp_type in ['text', 'password', 'search']:
                                data[name] = payload
                            else:
                                data[name] = 'test'

                    if data:
                        try:
                            if method == 'post':
                                test_response = await client.post(form_url, data=data, headers=self.headers)
                            else:
                                test_response = await client.get(form_url, params=data, headers=self.headers)

                            if self._contains_sql_error(test_response.text):
                                findings.append({
                                    'title': 'Error-Based SQL Injection',
                                    'severity': 'critical',
                                    'type': 'sqli_error',
                                    'url': form_url,
                                    'payload': payload,
                                    'description': 'Database error messages exposed, indicating SQL injection vulnerability'
                                })
                                break

                        except:
                            pass

        except:
            pass

        return findings

    async def _check_database_errors(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Check for exposed database errors"""
        findings = []

        try:
            response = await client.get(url, headers=self.headers)

            if self._contains_sql_error(response.text):
                findings.append({
                    'title': 'Database Error Information Disclosure',
                    'severity': 'medium',
                    'type': 'db_error',
                    'url': url,
                    'description': 'Database error messages are exposed in the response'
                })

        except:
            pass

        return findings

    async def _test_form_sqli(self, client: httpx.AsyncClient, base_url: str, form) -> List[Dict]:
        """Test specific form for SQL injection"""
        findings = []

        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        form_url = urljoin(base_url, action) if action else base_url

        inputs = form.find_all(['input', 'textarea'])

        # Boolean-based test
        true_payload = "1' AND '1'='1"
        false_payload = "1' AND '1'='2"

        data_true = {}
        data_false = {}

        for inp in inputs:
            name = inp.get('name')
            if name:
                inp_type = inp.get('type', 'text')
                if inp_type in ['text', 'password', 'search']:
                    data_true[name] = true_payload
                    data_false[name] = false_payload
                else:
                    data_true[name] = 'test'
                    data_false[name] = 'test'

        if data_true:
            try:
                # Send both payloads
                if method == 'post':
                    resp_true = await client.post(form_url, data=data_true, headers=self.headers)
                    resp_false = await client.post(form_url, data=data_false, headers=self.headers)
                else:
                    resp_true = await client.get(form_url, params=data_true, headers=self.headers)
                    resp_false = await client.get(form_url, params=data_false, headers=self.headers)

                # If responses differ significantly, might be vulnerable
                if resp_true.text != resp_false.text:
                    diff_ratio = abs(len(resp_true.text) - len(resp_false.text)) / max(len(resp_true.text), 1)

                    if diff_ratio > 0.1:  # 10% difference
                        findings.append({
                            'title': 'Boolean-Based SQL Injection',
                            'severity': 'critical',
                            'type': 'sqli_boolean',
                            'url': form_url,
                            'description': 'Form is vulnerable to boolean-based SQL injection',
                            'evidence': f'True condition: {len(resp_true.text)} bytes, False condition: {len(resp_false.text)} bytes'
                        })

            except:
                pass

        return findings

    async def _test_url_params_sqli(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Test URL parameters for SQL injection"""
        findings = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        # Test each parameter
        for param_name in params.keys():
            test_params = params.copy()
            test_params[param_name] = ["' OR '1'='1"]

            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

            try:
                response = await client.get(test_url, headers=self.headers)

                if self._contains_sql_error(response.text):
                    findings.append({
                        'title': f'SQL Injection in Parameter: {param_name}',
                        'severity': 'critical',
                        'type': 'sqli',
                        'url': url,
                        'parameter': param_name,
                        'payload': "' OR '1'='1",
                        'description': f'Parameter {param_name} is vulnerable to SQL injection'
                    })

            except:
                pass

        return findings

    async def _test_blind_sqli(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Test for blind SQL injection"""
        findings = []

        # Time-based blind SQLi payloads
        time_payloads = [
            "1' AND SLEEP(5)--",
            "1'; WAITFOR DELAY '00:00:05'--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ]

        try:
            response = await client.get(url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')

            for form in forms[:2]:  # Test first 2 forms
                action = form.get('action', '')
                form_url = urljoin(url, action) if action else url
                method = form.get('method', 'get').lower()

                inputs = form.find_all(['input', 'textarea'])

                for payload in time_payloads[:1]:  # Test one time-based payload
                    data = {}

                    for inp in inputs:
                        name = inp.get('name')
                        if name:
                            inp_type = inp.get('type', 'text')
                            if inp_type in ['text', 'password']:
                                data[name] = payload
                            else:
                                data[name] = 'test'

                    if data:
                        try:
                            import time
                            start_time = time.time()

                            if method == 'post':
                                await client.post(form_url, data=data, headers=self.headers, timeout=10.0)
                            else:
                                await client.get(form_url, params=data, headers=self.headers, timeout=10.0)

                            elapsed_time = time.time() - start_time

                            # If response took significantly longer, might be vulnerable
                            if elapsed_time > 4:
                                findings.append({
                                    'title': 'Time-Based Blind SQL Injection',
                                    'severity': 'critical',
                                    'type': 'sqli_blind',
                                    'url': form_url,
                                    'payload': payload,
                                    'description': f'Blind SQL injection detected - response delayed by {elapsed_time:.2f} seconds',
                                    'evidence': f'Response time: {elapsed_time:.2f}s'
                                })

                        except asyncio.TimeoutError:
                            # Timeout might indicate successful time-based injection
                            findings.append({
                                'title': 'Possible Time-Based Blind SQL Injection',
                                'severity': 'high',
                                'type': 'sqli_blind',
                                'url': form_url,
                                'payload': payload,
                                'description': 'Request timed out, indicating possible blind SQL injection'
                            })
                        except:
                            pass

        except:
            pass

        return findings

    async def _test_nosql_injection(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Test for NoSQL injection"""
        findings = []

        # NoSQL injection payloads
        nosql_payloads = [
            {'$ne': 'test'},
            {'$gt': ''},
            "' || '1'=='1",
            "admin' || '1'=='1",
        ]

        try:
            response = await client.get(url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')

            for form in forms[:2]:
                action = form.get('action', '')
                form_url = urljoin(url, action) if action else url
                method = form.get('method', 'get').lower()

                inputs = form.find_all(['input', 'textarea'])

                # Test with JSON payload
                json_payload = {}
                for inp in inputs:
                    name = inp.get('name')
                    if name:
                        json_payload[name] = {'$ne': ''}

                if json_payload:
                    try:
                        headers = self.headers.copy()
                        headers['Content-Type'] = 'application/json'

                        if method == 'post':
                            test_response = await client.post(form_url, json=json_payload, headers=headers)

                            # Check if bypass was successful
                            if test_response.status_code == 200 and 'error' not in test_response.text.lower():
                                findings.append({
                                    'title': 'NoSQL Injection Vulnerability',
                                    'severity': 'critical',
                                    'type': 'nosql',
                                    'url': form_url,
                                    'payload': str(json_payload),
                                    'description': 'Form is vulnerable to NoSQL injection'
                                })

                    except:
                        pass

        except:
            pass

        return findings

    def _contains_sql_error(self, text: str) -> bool:
        """Check if response contains SQL error messages"""
        sql_errors = [
            'sql syntax',
            'mysql_fetch',
            'mysql error',
            'postgresql',
            'ORA-',
            'SQL Server',
            'SQLite',
            'ODBC',
            'Microsoft Access',
            'JET Database',
            'Unclosed quotation mark',
            'syntax error',
            'unexpected end of SQL',
            'pg_query',
            'sqlite3',
            'SQLSTATE',
            'Warning: mysql',
            'valid MySQL result',
            'MySqlClient',
            'PostgreSQL query failed',
            'unterminated quoted string',
            'quoted string not properly terminated'
        ]

        text_lower = text.lower()
        for error in sql_errors:
            if error.lower() in text_lower:
                return True

        return False

    async def _run_sqlmap(self, target: str) -> List[Dict]:
        """Run sqlmap for automated SQL injection testing"""
        findings = []

        try:
            # Run sqlmap (simplified)
            result = subprocess.run(
                ['python3', '/opt/sqlmap/sqlmap.py', '-u', target, '--batch', '--random-agent', '--timeout=30'],
                capture_output=True,
                text=True,
                timeout=60
            )

            if 'vulnerable' in result.stdout.lower():
                findings.append({
                    'title': 'SQLMap Detected Vulnerability',
                    'severity': 'critical',
                    'type': 'sqlmap',
                    'url': target,
                    'description': 'SQLMap detected SQL injection vulnerability'
                })

        except Exception as e:
            pass

        return findings

scanner = DatabaseScanner()

@app.post("/scan")
async def scan_target(request: ScanRequest):
    """Execute database vulnerability scan"""

    if request.scan_type == "quick":
        results = await scanner.quick_scan(request.target)
    elif request.scan_type == "full":
        results = await scanner.full_scan(request.target)
    else:
        raise HTTPException(status_code=400, detail="Invalid scan type")

    return results

@app.get("/health")
async def health_check():
    return {"status": "healthy", "bot": "db-bot"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
