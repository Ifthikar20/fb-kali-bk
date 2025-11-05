"""Network Bot - Port Scanning and Network Analysis"""
import nmap
import asyncio
import subprocess
import json
from typing import List, Dict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import socket
import dns.resolver

app = FastAPI(title="Network Bot", version="1.0.0")

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"  # quick, full, stealth

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    async def quick_scan(self, target: str) -> Dict:
        """Quick port scan - top 1000 ports"""
        findings = []

        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(target)

            # Quick nmap scan
            self.nm.scan(ip, arguments='-F -T4')

            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()

                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        state = port_info['state']

                        if state == 'open':
                            service = port_info.get('name', 'unknown')
                            version = port_info.get('version', '')

                            # Check for critical services
                            severity = self._assess_port_severity(port, service)

                            finding = {
                                'title': f'Open Port {port}/{proto} - {service}',
                                'severity': severity,
                                'type': 'open_port',
                                'port': port,
                                'protocol': proto,
                                'service': service,
                                'version': version,
                                'ip': ip,
                                'description': f'Port {port} is open and running {service}'
                            }

                            findings.append(finding)

            # DNS enumeration
            dns_findings = await self._dns_enumeration(target)
            findings.extend(dns_findings)

        except Exception as e:
            findings.append({
                'title': 'Network Scan Error',
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
        """Full comprehensive scan"""
        findings = []

        try:
            ip = socket.gethostbyname(target)

            # Full port scan with service detection
            self.nm.scan(ip, arguments='-p- -sV -sC -T4 -A')

            for host in self.nm.all_hosts():
                # OS Detection
                if 'osmatch' in self.nm[host]:
                    for osmatch in self.nm[host]['osmatch']:
                        findings.append({
                            'title': f'OS Detection: {osmatch["name"]}',
                            'severity': 'info',
                            'type': 'os_detection',
                            'os': osmatch['name'],
                            'accuracy': osmatch['accuracy'],
                            'description': f'Detected OS: {osmatch["name"]} (Accuracy: {osmatch["accuracy"]}%)'
                        })

                # Port analysis
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()

                    for port in ports:
                        port_info = self.nm[host][proto][port]

                        if port_info['state'] == 'open':
                            service = port_info.get('name', 'unknown')
                            version = port_info.get('version', '')
                            product = port_info.get('product', '')

                            severity = self._assess_port_severity(port, service)

                            # Check for known vulnerable versions
                            if self._is_vulnerable_version(product, version):
                                severity = 'critical'

                            finding = {
                                'title': f'Open Port {port}/{proto} - {service}',
                                'severity': severity,
                                'type': 'open_port',
                                'port': port,
                                'protocol': proto,
                                'service': service,
                                'version': version,
                                'product': product,
                                'ip': ip,
                                'description': f'Port {port} running {product} {version}'
                            }

                            findings.append(finding)

        except Exception as e:
            findings.append({
                'title': 'Full Scan Error',
                'severity': 'info',
                'type': 'error',
                'description': str(e)
            })

        return {
            'scan_type': 'full',
            'target': target,
            'findings': findings
        }

    async def _dns_enumeration(self, target: str) -> List[Dict]:
        """DNS enumeration and subdomain discovery"""
        findings = []

        try:
            # Common DNS records
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']

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
                            'description': f'{record_type} record found: {str(rdata)}'
                        })
                except:
                    pass

            # Check for common subdomains
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test']

            for subdomain in common_subdomains:
                try:
                    full_domain = f'{subdomain}.{target}'
                    ip = socket.gethostbyname(full_domain)

                    findings.append({
                        'title': f'Subdomain Found: {subdomain}',
                        'severity': 'medium',
                        'type': 'subdomain',
                        'subdomain': full_domain,
                        'ip': ip,
                        'description': f'Subdomain {full_domain} resolves to {ip}'
                    })
                except:
                    pass

        except Exception as e:
            pass

        return findings

    def _assess_port_severity(self, port: int, service: str) -> str:
        """Assess severity based on port and service"""
        # Critical ports (commonly exploited)
        critical_ports = [21, 22, 23, 3389, 445, 139, 1433, 3306, 5432, 27017, 6379]

        # High risk services
        high_risk_services = ['telnet', 'ftp', 'smb', 'mysql', 'postgresql', 'mongodb', 'redis']

        if port in critical_ports:
            return 'high'

        if service.lower() in high_risk_services:
            return 'high'

        # Medium for all other open ports
        if port < 1024:
            return 'medium'

        return 'low'

    def _is_vulnerable_version(self, product: str, version: str) -> bool:
        """Check for known vulnerable versions"""
        # Simplified vulnerability check
        vulnerable_versions = {
            'OpenSSH': ['7.4', '7.3', '6.6'],
            'Apache': ['2.4.49', '2.4.50'],
            'nginx': ['1.18.0', '1.17.0']
        }

        for vuln_product, vuln_versions in vulnerable_versions.items():
            if vuln_product.lower() in product.lower():
                if version in vuln_versions:
                    return True

        return False

scanner = NetworkScanner()

@app.post("/scan")
async def scan_target(request: ScanRequest):
    """Execute network scan"""

    if request.scan_type == "quick":
        results = await scanner.quick_scan(request.target)
    elif request.scan_type == "full":
        results = await scanner.full_scan(request.target)
    else:
        raise HTTPException(status_code=400, detail="Invalid scan type")

    return results

@app.get("/health")
async def health_check():
    return {"status": "healthy", "bot": "network-bot"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
