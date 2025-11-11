#!/usr/bin/env python3
"""
FetchBot MCP Security Tools Server

Exposes security testing tools via Model Context Protocol.
Claude can directly invoke these tools with streaming support.
"""

import asyncio
import subprocess
import json
import nmap
from typing import Any, Sequence
from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import AnyUrl

# Initialize MCP server
app = Server("fetchbot-security-tools")

# Port scanner instance
nm = nmap.PortScanner()


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available security testing tools"""
    return [
        Tool(
            name="nmap_scan",
            description="Scan target for open ports and services using nmap",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target domain or IP address"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "full", "stealth"],
                        "description": "Type of scan to perform",
                        "default": "quick"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="http_scan",
            description="Scan HTTP/HTTPS endpoint for technologies and structure",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to scan"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="directory_fuzzing",
            description="Fuzz web directories to discover hidden paths",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Base URL to fuzz"
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to wordlist file",
                        "default": "/usr/share/seclists/Discovery/Web-Content/common.txt"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="sql_injection_test",
            description="Test endpoint for SQL injection vulnerabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL with injectable parameter"
                    },
                    "parameter": {
                        "type": "string",
                        "description": "Parameter name to test"
                    }
                },
                "required": ["url", "parameter"]
            }
        ),
        Tool(
            name="xss_test",
            description="Test endpoint for XSS vulnerabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to test"
                    },
                    "input_field": {
                        "type": "string",
                        "description": "Form field or parameter to test"
                    }
                },
                "required": ["url", "input_field"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> Sequence[TextContent]:
    """Execute security tool and stream results"""

    if name == "nmap_scan":
        return await execute_nmap(arguments)
    elif name == "http_scan":
        return await execute_http_scan(arguments)
    elif name == "directory_fuzzing":
        return await execute_directory_fuzzing(arguments)
    elif name == "sql_injection_test":
        return await execute_sql_injection_test(arguments)
    elif name == "xss_test":
        return await execute_xss_test(arguments)
    else:
        raise ValueError(f"Unknown tool: {name}")


async def execute_nmap(args: dict) -> Sequence[TextContent]:
    """Execute nmap scan with streaming output"""
    target = args["target"]
    scan_type = args.get("scan_type", "quick")

    # Map scan type to nmap arguments
    scan_args = {
        "quick": "-F -T4",
        "full": "-p- -sV -T4 -A",
        "stealth": "-sS -T2"
    }

    nmap_args = scan_args.get(scan_type, "-F -T4")

    # Run nmap
    nm.scan(target, arguments=nmap_args)

    # Parse results
    results = []
    for host in nm.all_hosts():
        host_info = {
            "host": host,
            "state": nm[host].state(),
            "open_ports": []
        }

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                port_info = nm[host][proto][port]
                if port_info['state'] == 'open':
                    host_info['open_ports'].append({
                        'port': port,
                        'protocol': proto,
                        'service': port_info.get('name', 'unknown'),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', '')
                    })

        results.append(host_info)

    # Format output
    output = f"Nmap scan completed for {target}\n\n"
    for host in results:
        output += f"Host: {host['host']} ({host['state']})\n"
        output += f"Open ports: {len(host['open_ports'])}\n\n"

        for port in host['open_ports']:
            output += f"  {port['port']}/{port['protocol']}: {port['service']}"
            if port['version']:
                output += f" {port['version']}"
            output += "\n"

    return [TextContent(type="text", text=output)]


async def execute_http_scan(args: dict) -> Sequence[TextContent]:
    """Scan HTTP endpoint for technologies"""
    import httpx
    from bs4 import BeautifulSoup

    url = args["url"]

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url)

        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')

        # Detect technologies
        techs = []

        # Check for common frameworks
        if soup.find('meta', {'name': 'generator'}):
            techs.append(soup.find('meta', {'name': 'generator'})['content'])

        # Check headers
        server = response.headers.get('server', '')
        if server:
            techs.append(f"Server: {server}")

        x_powered_by = response.headers.get('x-powered-by', '')
        if x_powered_by:
            techs.append(f"Powered by: {x_powered_by}")

        # Find links
        links = [a.get('href') for a in soup.find_all('a') if a.get('href')]

        # Find forms
        forms = soup.find_all('form')

        output = f"HTTP Scan Results for {url}\n\n"
        output += f"Status: {response.status_code}\n"
        output += f"Technologies detected: {', '.join(techs) if techs else 'None'}\n"
        output += f"Links found: {len(links)}\n"
        output += f"Forms found: {len(forms)}\n\n"

        if forms:
            output += "Forms:\n"
            for i, form in enumerate(forms[:5]):  # Limit to 5
                action = form.get('action', 'N/A')
                method = form.get('method', 'GET')
                output += f"  {i+1}. {method} {action}\n"

        return [TextContent(type="text", text=output)]


async def execute_directory_fuzzing(args: dict) -> Sequence[TextContent]:
    """Fuzz directories using ffuf or similar"""
    url = args["url"]
    wordlist = args.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")

    # Use ffuf for fuzzing
    cmd = [
        "ffuf",
        "-u", f"{url}/FUZZ",
        "-w", wordlist,
        "-mc", "200,204,301,302,307,401,403",
        "-fs", "0",
        "-t", "50",
        "-o", "/tmp/ffuf_output.json",
        "-of", "json"
    ]

    # Run ffuf
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    # Parse results
    try:
        with open('/tmp/ffuf_output.json', 'r') as f:
            results = json.load(f)

        output = f"Directory Fuzzing Results for {url}\n\n"
        output += f"Directories found: {len(results.get('results', []))}\n\n"

        for result in results.get('results', [])[:20]:  # Limit to 20
            path = result.get('input', {}).get('FUZZ', '')
            status = result.get('status', 0)
            length = result.get('length', 0)
            output += f"  {status} {url}/{path} ({length} bytes)\n"

        return [TextContent(type="text", text=output)]
    except Exception as e:
        return [TextContent(type="text", text=f"Fuzzing failed: {str(e)}")]


async def execute_sql_injection_test(args: dict) -> Sequence[TextContent]:
    """Test for SQL injection vulnerabilities"""
    url = args["url"]
    parameter = args["parameter"]

    import httpx

    # Test payloads
    payloads = [
        "'",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2"
    ]

    results = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        for payload in payloads:
            test_url = url.replace(f"{parameter}=", f"{parameter}={payload}")

            try:
                response = await client.get(test_url)

                # Check for SQL errors
                sql_errors = [
                    "sql syntax", "mysql", "postgresql", "oracle",
                    "syntax error", "unclosed quotation", "quoted string"
                ]

                has_error = any(err in response.text.lower() for err in sql_errors)

                results.append({
                    "payload": payload,
                    "status": response.status_code,
                    "sql_error": has_error,
                    "length": len(response.text)
                })
            except Exception as e:
                results.append({
                    "payload": payload,
                    "error": str(e)
                })

    # Analyze results
    vulnerable = any(r.get('sql_error', False) for r in results)

    output = f"SQL Injection Test for {url}\n\n"
    output += f"Vulnerability: {'DETECTED' if vulnerable else 'Not detected'}\n\n"

    for result in results:
        if result.get('sql_error'):
            output += f"  ⚠️  Payload '{result['payload']}' triggered SQL error\n"
        elif 'error' in result:
            output += f"  ❌ Payload '{result['payload']}' caused error: {result['error']}\n"

    return [TextContent(type="text", text=output)]


async def execute_xss_test(args: dict) -> Sequence[TextContent]:
    """Test for XSS vulnerabilities"""
    url = args["url"]
    input_field = args["input_field"]

    import httpx

    # XSS payloads
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "'><script>alert(1)</script>"
    ]

    results = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        for payload in payloads:
            test_url = url.replace(f"{input_field}=", f"{input_field}={payload}")

            try:
                response = await client.get(test_url)

                # Check if payload is reflected
                reflected = payload in response.text

                results.append({
                    "payload": payload,
                    "reflected": reflected,
                    "status": response.status_code
                })
            except Exception as e:
                results.append({
                    "payload": payload,
                    "error": str(e)
                })

    # Analyze results
    vulnerable = any(r.get('reflected', False) for r in results)

    output = f"XSS Test for {url}\n\n"
    output += f"Vulnerability: {'DETECTED' if vulnerable else 'Not detected'}\n\n"

    for result in results:
        if result.get('reflected'):
            output += f"  ⚠️  Payload '{result['payload']}' was reflected in response\n"

    return [TextContent(type="text", text=output)]


async def main():
    """Run the MCP server"""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
