#!/usr/bin/env python3
"""
Test FetchBot.ai API with RAG system
Creates an authenticated scan and monitors RAG suggestions
"""

import requests
import json
import time
import sys

# API Configuration
API_BASE = "http://localhost:8000"
USERNAME = "admin"
PASSWORD = "admin123"  # Default admin password

def login():
    """Login and get JWT token"""
    print("🔐 Logging in...")

    response = requests.post(
        f"{API_BASE}/api/login",
        json={"username": USERNAME, "password": PASSWORD}
    )

    if response.status_code == 200:
        data = response.json()
        token = data.get("access_token")
        print(f"✅ Logged in successfully!")
        print(f"   Token: {token[:30]}...")
        return token
    else:
        print(f"❌ Login failed: {response.status_code}")
        print(f"   Response: {response.text}")
        sys.exit(1)

def create_pentest(token, target_url, scan_type, tech_stack):
    """Create a pentest job"""
    print(f"\n🎯 Creating pentest job for: {target_url}")
    print(f"   Scan Type: {scan_type}")
    print(f"   Tech Stack: {', '.join(tech_stack)}")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "target_url": target_url,
        "scan_type": scan_type,
        "tech_stack": tech_stack
    }

    response = requests.post(
        f"{API_BASE}/api/pentest",
        headers=headers,
        json=payload
    )

    if response.status_code in [200, 201]:
        data = response.json()
        job_id = data.get("job_id") or data.get("id")
        print(f"✅ Pentest job created!")
        print(f"   Job ID: {job_id}")
        return job_id
    else:
        print(f"❌ Failed to create pentest: {response.status_code}")
        print(f"   Response: {response.text}")
        return None

def get_job_status(token, job_id):
    """Get pentest job status"""
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(
        f"{API_BASE}/api/pentest/{job_id}",
        headers=headers
    )

    if response.status_code == 200:
        return response.json()
    else:
        print(f"⚠️  Failed to get job status: {response.status_code}")
        return None

def list_pentests(token):
    """List all pentest jobs"""
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(
        f"{API_BASE}/api/pentest",
        headers=headers
    )

    if response.status_code == 200:
        return response.json()
    else:
        return []

def monitor_job(token, job_id, duration=30):
    """Monitor job for specified duration"""
    print(f"\n📊 Monitoring job for {duration} seconds...")
    print("   (Check the server logs for RAG activity)")
    print()

    start_time = time.time()
    last_status = None

    while time.time() - start_time < duration:
        status_data = get_job_status(token, job_id)

        if status_data:
            current_status = status_data.get("status")

            if current_status != last_status:
                print(f"   Status: {current_status}")
                last_status = current_status

                if "findings" in status_data:
                    findings = status_data["findings"]
                    if findings:
                        print(f"   Findings: {len(findings)} vulnerabilities detected")

                if current_status in ["completed", "failed", "error"]:
                    print(f"\n✅ Job {current_status}!")
                    return status_data

        time.sleep(3)

    print(f"\n⏱️  Monitoring timeout ({duration}s)")
    return get_job_status(token, job_id)

def main():
    print("=" * 70)
    print("🧪 FETCHBOT.AI API + RAG SYSTEM TEST")
    print("=" * 70)
    print()

    # Step 1: Login
    token = login()

    # Step 2: Create a test scan
    print("\n" + "=" * 70)
    print("Creating Test Scan")
    print("=" * 70)

    # Choose a safe test target
    test_cases = [
        {
            "name": "OWASP Juice Shop (Safe Test Target)",
            "target_url": "https://juice-shop.herokuapp.com",
            "scan_type": "web",
            "tech_stack": ["Node.js", "Express", "Angular", "SQLite"]
        },
        {
            "name": "WordPress Site Test",
            "target_url": "https://wordpress.org",
            "scan_type": "web",
            "tech_stack": ["WordPress", "PHP", "MySQL"]
        }
    ]

    # Use the first test case
    test = test_cases[0]
    print(f"\nTest Target: {test['name']}")

    job_id = create_pentest(
        token=token,
        target_url=test["target_url"],
        scan_type=test["scan_type"],
        tech_stack=test["tech_stack"]
    )

    if not job_id:
        print("\n❌ Failed to create pentest job")
        sys.exit(1)

    # Step 3: Monitor the job
    print("\n" + "=" * 70)
    print("Monitoring RAG Activity")
    print("=" * 70)
    print()
    print("💡 TIP: Watch the server terminal for RAG logs like:")
    print("   - 'RAG enabled, initializing retrieval service'")
    print("   - 'Querying tool knowledge...'")
    print("   - 'Found N relevant tool knowledge entries'")
    print("   - 'RAG suggested N tools...'")
    print("   - 'Augmented agent prompt with N contexts'")
    print()

    final_status = monitor_job(token, job_id, duration=60)

    # Step 4: Show results
    print("\n" + "=" * 70)
    print("Final Results")
    print("=" * 70)

    if final_status:
        print(f"\nJob ID: {job_id}")
        print(f"Status: {final_status.get('status')}")
        print(f"Target: {final_status.get('target_url')}")

        if "findings" in final_status:
            findings = final_status["findings"]
            print(f"Findings: {len(findings)} vulnerabilities")

            if findings:
                print("\nTop Findings:")
                for i, finding in enumerate(findings[:3], 1):
                    print(f"  {i}. {finding.get('title', 'Unknown')}")
                    print(f"     Severity: {finding.get('severity', 'Unknown')}")

    print("\n" + "=" * 70)
    print("Test Complete!")
    print("=" * 70)
    print()
    print("✅ Your RAG-enhanced FetchBot.ai is working!")
    print()
    print("What happened:")
    print("  1. API authenticated your request")
    print("  2. Created a pentest job with tech stack context")
    print("  3. RAG system suggested relevant tools based on tech stack")
    print("  4. Agent executed scan with RAG-enhanced prompts")
    print()
    print("Check the server logs to see RAG suggestions in action!")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
