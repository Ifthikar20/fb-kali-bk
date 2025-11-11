"""
Dynamic Container Manager

Spawns and manages Kali agent containers dynamically for each scan.
Each scan gets fresh containers with the target URL as an environment variable.
"""

import docker
import logging
import asyncio
import time
import httpx
from typing import List, Dict, Any, Optional
from docker.models.containers import Container
from docker.errors import DockerException, APIError

logger = logging.getLogger(__name__)


class DynamicContainerManager:
    """
    Manages dynamic Kali agent containers for security scans

    Features:
    - Spawns fresh containers per scan with target URL
    - Waits for container health checks
    - Cleans up containers after scan completion
    - Handles container networking and port allocation
    """

    def __init__(self, network_name: str = "fetchbot_fetchbot"):
        """
        Initialize container manager

        Args:
            network_name: Docker network to attach containers to
        """
        import os

        # Try multiple methods to connect to Docker on macOS
        connection_methods = [
            ("default from_env()", lambda: docker.from_env()),
            ("unix:///var/run/docker.sock", lambda: docker.DockerClient(base_url='unix:///var/run/docker.sock')),
            (f"unix://{os.path.expanduser('~')}/.docker/run/docker.sock",
             lambda: docker.DockerClient(base_url=f"unix://{os.path.expanduser('~')}/.docker/run/docker.sock")),
        ]

        last_error = None
        for method_name, connect_func in connection_methods:
            try:
                logger.info(f"Attempting Docker connection via: {method_name}")
                self.client = connect_func()
                # Test the connection
                self.client.ping()
                self.network_name = network_name
                logger.info(f"✓ Docker client initialized successfully via: {method_name}")
                return
            except Exception as e:
                logger.debug(f"Failed to connect via {method_name}: {e}")
                last_error = e
                continue

        # If we get here, all methods failed
        error_msg = (
            "Could not connect to Docker. Please ensure Docker Desktop is running.\n"
            "On macOS: Check that Docker Desktop is running in your Applications.\n"
            f"Last error: {last_error}"
        )
        logger.error(error_msg)
        raise DockerException(error_msg)

    async def spawn_kali_agents(
        self,
        job_id: str,
        target_url: str,
        num_agents: int = 3,
        base_port: int = 9100
    ) -> List[Dict[str, Any]]:
        """
        Spawn dynamic Kali agent containers for a scan

        Args:
            job_id: Unique job identifier (used in container names)
            target_url: Target URL to scan
            num_agents: Number of agents to spawn
            base_port: Starting port number for agents

        Returns:
            List of agent info dictionaries with container_id, agent_url, container_name
        """
        logger.info(f"Spawning {num_agents} Kali agents for job {job_id} targeting {target_url}")

        agents = []
        containers_to_cleanup = []

        try:
            # Ensure the Kali agent image is built
            await self._ensure_kali_image()

            for i in range(num_agents):
                agent_num = i + 1
                container_name = f"kali-agent-{job_id}-{agent_num}"
                host_port = base_port + i

                logger.info(f"Starting container {container_name} on port {host_port}")

                # Spawn container
                container = self.client.containers.run(
                    image="fetchbot-kali-agent:latest",
                    name=container_name,
                    environment={
                        "AGENT_ID": container_name,
                        "AGENT_PORT": "9000",
                        "TARGET_URL": target_url,
                        "JOB_ID": job_id
                    },
                    ports={"9000/tcp": host_port},
                    network=self.network_name,
                    cap_add=["NET_ADMIN", "NET_RAW"],
                    detach=True,
                    remove=False,  # We'll remove manually after scan
                    labels={
                        "job_id": job_id,
                        "component": "kali-agent",
                        "managed_by": "fetchbot-dynamic"
                    }
                )

                containers_to_cleanup.append(container)

                # Use localhost with host port since API server runs on host machine
                agent_url = f"http://localhost:{host_port}"

                agents.append({
                    "container_id": container.id,
                    "container_name": container_name,
                    "agent_url": agent_url,
                    "host_port": host_port,
                    "target_url": target_url
                })

                logger.info(f"Container {container_name} started: {container.id[:12]}")

            # Wait for all agents to become healthy
            await self._wait_for_agents_health(agents, timeout=120)

            logger.info(f"Successfully spawned {len(agents)} Kali agents for job {job_id}")
            return agents

        except Exception as e:
            logger.error(f"Failed to spawn Kali agents: {e}")
            # Clean up any containers that were started
            await self._cleanup_containers(containers_to_cleanup)
            raise

    async def _ensure_kali_image(self):
        """Ensure the Kali agent Docker image is built"""
        try:
            # Check if image exists
            self.client.images.get("fetchbot-kali-agent:latest")
            logger.info("Kali agent image found")
        except docker.errors.ImageNotFound:
            logger.warning("Kali agent image not found, attempting to build...")
            # Image will need to be built manually or via docker-compose
            # We don't auto-build here to avoid blocking
            raise RuntimeError(
                "Kali agent image 'fetchbot-kali-agent:latest' not found. "
                "Please build it using: docker-compose -f docker-compose-multi-kali.yml build"
            )

    async def _wait_for_agents_health(
        self,
        agents: List[Dict[str, Any]],
        timeout: int = 120,
        poll_interval: int = 2
    ):
        """
        Wait for all agents to become healthy

        Args:
            agents: List of agent info dictionaries
            timeout: Maximum time to wait in seconds
            poll_interval: Time between health checks in seconds
        """
        logger.info(f"Waiting for {len(agents)} agents to become healthy (timeout: {timeout}s)")

        start_time = time.time()
        healthy_agents = set()

        async with httpx.AsyncClient(timeout=5.0) as client:
            while time.time() - start_time < timeout:
                for agent in agents:
                    if agent["container_name"] in healthy_agents:
                        continue

                    try:
                        # Try to reach the health endpoint
                        response = await client.get(
                            f"http://localhost:{agent['host_port']}/health"
                        )
                        if response.status_code == 200:
                            healthy_agents.add(agent["container_name"])
                            logger.info(f"Agent {agent['container_name']} is healthy")
                    except (httpx.RequestError, httpx.HTTPStatusError):
                        # Agent not ready yet
                        pass

                # Check if all agents are healthy
                if len(healthy_agents) == len(agents):
                    logger.info(f"All {len(agents)} agents are healthy")
                    return

                # Wait before next poll
                await asyncio.sleep(poll_interval)

        # Timeout reached
        unhealthy = [a["container_name"] for a in agents if a["container_name"] not in healthy_agents]
        raise TimeoutError(
            f"Timeout waiting for agents to become healthy. "
            f"Unhealthy agents: {unhealthy}"
        )

    async def cleanup_job_containers(self, job_id: str, force: bool = True):
        """
        Clean up all containers associated with a job

        Args:
            job_id: Job identifier
            force: If True, force remove containers even if running
        """
        logger.info(f"Cleaning up containers for job {job_id}")

        try:
            # Find all containers with the job_id label
            containers = self.client.containers.list(
                all=True,
                filters={"label": f"job_id={job_id}"}
            )

            if not containers:
                logger.info(f"No containers found for job {job_id}")
                return

            for container in containers:
                try:
                    container_name = container.name
                    logger.info(f"Stopping container {container_name}")
                    container.stop(timeout=10)
                    logger.info(f"Removing container {container_name}")
                    container.remove(force=force)
                    logger.info(f"Container {container_name} removed")
                except APIError as e:
                    logger.error(f"Failed to remove container {container.name}: {e}")

            logger.info(f"Cleanup complete for job {job_id}")

        except Exception as e:
            logger.error(f"Error during container cleanup for job {job_id}: {e}")
            raise

    async def _cleanup_containers(self, containers: List[Container]):
        """Clean up a list of containers (used for error handling)"""
        for container in containers:
            try:
                logger.info(f"Cleaning up container {container.name}")
                container.stop(timeout=5)
                container.remove(force=True)
            except Exception as e:
                logger.error(f"Failed to cleanup container {container.name}: {e}")

    def get_job_containers(self, job_id: str) -> List[Dict[str, Any]]:
        """
        Get information about all containers for a job

        Args:
            job_id: Job identifier

        Returns:
            List of container info dictionaries
        """
        try:
            containers = self.client.containers.list(
                all=True,
                filters={"label": f"job_id={job_id}"}
            )

            return [
                {
                    "id": c.id[:12],
                    "name": c.name,
                    "status": c.status,
                    "image": c.image.tags[0] if c.image.tags else "unknown"
                }
                for c in containers
            ]
        except Exception as e:
            logger.error(f"Failed to get containers for job {job_id}: {e}")
            return []

    def close(self):
        """Close the Docker client connection"""
        try:
            self.client.close()
            logger.info("Docker client closed")
        except Exception as e:
            logger.error(f"Error closing Docker client: {e}")


# Global instance (optional - can be instantiated per request)
_container_manager: Optional[DynamicContainerManager] = None


def get_container_manager() -> DynamicContainerManager:
    """Get or create the global container manager instance"""
    global _container_manager
    if _container_manager is None:
        _container_manager = DynamicContainerManager()
    return _container_manager
