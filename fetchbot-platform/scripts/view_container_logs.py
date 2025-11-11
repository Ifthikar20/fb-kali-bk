#!/usr/bin/env python3
"""
View logs from dynamic Kali agent containers
"""

import sys
import os
import argparse
import docker
from datetime import datetime
from typing import List, Dict
import subprocess

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils.container_manager import get_container_manager


class ContainerLogViewer:
    """View logs from dynamic Kali agent containers"""

    def __init__(self):
        try:
            self.client = docker.from_env()
        except Exception as e:
            print(f"❌ Could not connect to Docker: {e}")
            sys.exit(1)

    def list_containers(self, all_containers: bool = False) -> List[Dict]:
        """List all dynamic agent containers"""
        filters = {"label": "managed_by=fetchbot-dynamic"}
        containers = self.client.containers.list(all=all_containers, filters=filters)

        container_info = []
        for container in containers:
            labels = container.labels
            info = {
                "id": container.id[:12],
                "name": container.name,
                "status": container.status,
                "job_id": labels.get("job_id", "N/A"),
                "created": container.attrs["Created"],
                "ports": container.ports
            }
            container_info.append(info)

        return container_info

    def print_container_table(self, all_containers: bool = False):
        """Print formatted table of containers"""
        containers = self.list_containers(all_containers)

        if not containers:
            print("ℹ️  No dynamic agent containers found")
            return

        print("\n📦 Dynamic Kali Agent Containers:\n")
        print(f"{'Name':<50} {'Status':<12} {'Job ID':<40} {'Port':<10}")
        print("=" * 120)

        for c in containers:
            # Extract port mapping
            port_mapping = ""
            if c["ports"]:
                for port_info in c["ports"].values():
                    if port_info:
                        port_mapping = f"{port_info[0]['HostPort']}"
                        break

            status_emoji = "✅" if c["status"] == "running" else "🔴"
            print(f"{c['name']:<50} {status_emoji} {c['status']:<10} {c['job_id']:<40} {port_mapping:<10}")

        print(f"\nTotal: {len(containers)} containers")

        # Count by status
        running = sum(1 for c in containers if c["status"] == "running")
        stopped = len(containers) - running
        print(f"Running: {running}  Stopped: {stopped}\n")

    def get_containers_by_job(self, job_id: str) -> List:
        """Get containers for a specific job"""
        filters = {
            "label": [
                "managed_by=fetchbot-dynamic",
                f"job_id={job_id}"
            ]
        }
        return self.client.containers.list(filters=filters)

    def view_logs(self, job_id: str = None, follow: bool = False, tail: int = 100):
        """View logs from containers"""
        if job_id:
            containers = self.get_containers_by_job(job_id)
            if not containers:
                print(f"❌ No running containers found for job: {job_id}")
                return
        else:
            filters = {"label": "managed_by=fetchbot-dynamic"}
            containers = self.client.containers.list(filters=filters)
            if not containers:
                print("ℹ️  No running dynamic agent containers found")
                return

        print(f"\n📋 Viewing logs from {len(containers)} container(s)...\n")

        if follow:
            # Use Docker API for real-time streaming
            import threading
            import queue

            log_queue = queue.Queue()
            stop_event = threading.Event()

            def stream_container_logs(container, q, stop):
                """Stream logs from a container in a thread"""
                try:
                    name = container.name[-10:]  # Last 10 chars
                    # Stream logs with timestamps
                    for line in container.logs(stream=True, follow=True, tail=tail):
                        if stop.is_set():
                            break
                        decoded = line.decode('utf-8').rstrip()
                        q.put(f"[{name}] {decoded}")
                except Exception as e:
                    q.put(f"[{container.name[-10:]}] ERROR: {e}")

            # Start threads for each container
            threads = []
            for container in containers:
                print(f"🔄 Following logs from: {container.name}")
                t = threading.Thread(
                    target=stream_container_logs,
                    args=(container, log_queue, stop_event),
                    daemon=True
                )
                t.start()
                threads.append(t)

            print("\n" + "="*80)
            print("📺 Live logs (Ctrl+C to stop):")
            print("="*80 + "\n")

            try:
                while True:
                    try:
                        # Get logs from queue with timeout
                        log_line = log_queue.get(timeout=0.1)
                        print(log_line, flush=True)  # Force flush for real-time output
                    except queue.Empty:
                        # Check if containers still exist
                        still_running = False
                        for container in containers:
                            try:
                                container.reload()
                                if container.status == 'running':
                                    still_running = True
                                    break
                            except:
                                pass
                        if not still_running:
                            print("\n⏹️  All containers have stopped")
                            break
            except KeyboardInterrupt:
                print("\n\n⏹️  Stopped following logs")
            finally:
                stop_event.set()
                # Wait a bit for threads to finish
                for t in threads:
                    t.join(timeout=1)
        else:
            # Show last N lines from each container
            for container in containers:
                print(f"\n{'='*80}")
                print(f"📄 Logs from: {container.name}")
                print(f"   Job ID: {container.labels.get('job_id', 'N/A')}")
                print(f"   Status: {container.status}")
                print(f"{'='*80}\n")

                logs = container.logs(tail=tail, timestamps=True).decode('utf-8')
                print(logs)

    def cleanup_stopped_containers(self):
        """Remove all stopped dynamic agent containers"""
        containers = self.list_containers(all_containers=True)
        stopped = [c for c in containers if c["status"] != "running"]

        if not stopped:
            print("✅ No stopped containers to clean up")
            return

        print(f"\n🧹 Found {len(stopped)} stopped container(s)")
        response = input("Remove them? (y/N): ")

        if response.lower() == 'y':
            for c in stopped:
                try:
                    container = self.client.containers.get(c["id"])
                    container.remove()
                    print(f"  ✓ Removed: {c['name']}")
                except Exception as e:
                    print(f"  ✗ Failed to remove {c['name']}: {e}")
            print(f"\n✅ Cleanup complete")
        else:
            print("❌ Cleanup cancelled")


def main():
    parser = argparse.ArgumentParser(
        description="View logs from dynamic Kali agent containers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --list                        # List all dynamic containers
  %(prog)s --list --all                  # List all (including stopped)
  %(prog)s --job-id abc123               # View logs for specific job
  %(prog)s --follow                      # Follow logs from all running agents
  %(prog)s --job-id abc123 --follow      # Follow logs for specific job
  %(prog)s --cleanup                     # Remove stopped containers
        """
    )

    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List all dynamic containers"
    )

    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Include stopped containers (with --list)"
    )

    parser.add_argument(
        "-j", "--job-id",
        help="View logs for specific job ID"
    )

    parser.add_argument(
        "-f", "--follow",
        action="store_true",
        help="Follow log output (like tail -f)"
    )

    parser.add_argument(
        "-n", "--tail",
        type=int,
        default=100,
        help="Number of lines to show (default: 100)"
    )

    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove all stopped dynamic containers"
    )

    args = parser.parse_args()

    viewer = ContainerLogViewer()

    if args.cleanup:
        viewer.cleanup_stopped_containers()
    elif args.list:
        viewer.print_container_table(all_containers=args.all)
    else:
        viewer.view_logs(
            job_id=args.job_id,
            follow=args.follow,
            tail=args.tail
        )


if __name__ == "__main__":
    main()
