"""
Work Queue with Deduplication

Thread-safe work queue that ensures no duplicate testing across agents
"""

import asyncio
import hashlib
import json
import logging
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)


class WorkItemStatus(Enum):
    """Status of work items"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class WorkQueue:
    """
    Thread-safe work queue with deduplication

    Ensures that:
    - No work item is tested twice
    - Work is distributed to appropriate agent types
    - Failed work can be retried
    - Work status is tracked
    """

    def __init__(self):
        """Initialize work queue"""
        # Work items by agent type: {agent_type: [work_items]}
        self.pending: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        # Work items currently being processed: {work_hash: work_item}
        self.in_progress: Dict[str, Dict[str, Any]] = {}

        # Completed work items: {work_hash: result}
        self.completed: Dict[str, Dict[str, Any]] = {}

        # Failed work items: {work_hash: error}
        self.failed: Dict[str, Dict[str, Any]] = {}

        # Lock for thread safety
        self.lock = asyncio.Lock()

        # Metrics
        self.total_added = 0
        self.total_completed = 0
        self.duplicates_prevented = 0

        logger.info("Work queue initialized")

    def _hash_work_item(self, work_item: Dict[str, Any]) -> str:
        """
        Generate unique hash for work item

        Args:
            work_item: Work item dict with tool and params

        Returns:
            SHA256 hash of work item
        """
        # Create deterministic string from work item
        tool = work_item["tool"]
        params = work_item.get("params", {})

        # Sort params to ensure consistent hashing
        params_str = json.dumps(params, sort_keys=True)

        # Combine tool and params
        work_str = f"{tool}:{params_str}"

        # Generate hash
        return hashlib.sha256(work_str.encode()).hexdigest()

    async def add_work(
        self,
        agent_type: str,
        tool: str,
        params: Dict[str, Any],
        priority: int = 0
    ) -> bool:
        """
        Add work item to queue

        Args:
            agent_type: Type of agent that should handle this work
            tool: Tool name to execute
            params: Tool parameters
            priority: Priority level (higher = more urgent)

        Returns:
            True if work was added, False if duplicate
        """
        work_item = {
            "tool": tool,
            "params": params,
            "agent_type": agent_type,
            "priority": priority,
            "added_at": datetime.utcnow().isoformat()
        }

        work_hash = self._hash_work_item(work_item)

        async with self.lock:
            # Check if already completed or in progress
            if work_hash in self.completed:
                self.duplicates_prevented += 1
                logger.debug(
                    f"Work item already completed: {tool} with {params}"
                )
                return False

            if work_hash in self.in_progress:
                self.duplicates_prevented += 1
                logger.debug(
                    f"Work item already in progress: {tool} with {params}"
                )
                return False

            # Check if already pending
            for pending_item in self.pending[agent_type]:
                if self._hash_work_item(pending_item) == work_hash:
                    self.duplicates_prevented += 1
                    logger.debug(
                        f"Work item already pending: {tool} with {params}"
                    )
                    return False

            # Add to pending queue
            work_item["hash"] = work_hash
            self.pending[agent_type].append(work_item)

            # Sort by priority (higher priority first)
            self.pending[agent_type].sort(
                key=lambda x: x["priority"],
                reverse=True
            )

            self.total_added += 1

            logger.info(
                f"Added work item: {tool} for {agent_type} "
                f"(queue: {len(self.pending[agent_type])})"
            )

            return True

    async def get_work(self, agent_type: str) -> Optional[Dict[str, Any]]:
        """
        Get next work item for agent type

        Args:
            agent_type: Type of agent requesting work

        Returns:
            Work item dict or None if no work available
        """
        async with self.lock:
            if agent_type not in self.pending or not self.pending[agent_type]:
                return None

            # Get highest priority work item
            work_item = self.pending[agent_type].pop(0)
            work_hash = work_item["hash"]

            # Mark as in progress
            work_item["started_at"] = datetime.utcnow().isoformat()
            self.in_progress[work_hash] = work_item

            logger.info(
                f"Dispatched work item: {work_item['tool']} to {agent_type}"
            )

            return work_item

    async def mark_completed(
        self,
        work_item: Dict[str, Any],
        result: Dict[str, Any]
    ):
        """
        Mark work item as completed

        Args:
            work_item: The work item that was completed
            result: Result of executing the work item
        """
        work_hash = work_item["hash"]

        async with self.lock:
            # Remove from in_progress
            if work_hash in self.in_progress:
                del self.in_progress[work_hash]

            # Add to completed
            self.completed[work_hash] = {
                "work_item": work_item,
                "result": result,
                "completed_at": datetime.utcnow().isoformat()
            }

            self.total_completed += 1

            logger.info(
                f"Marked completed: {work_item['tool']} "
                f"({self.total_completed}/{self.total_added})"
            )

    async def mark_failed(
        self,
        work_item: Dict[str, Any],
        error: str,
        retry: bool = False
    ):
        """
        Mark work item as failed

        Args:
            work_item: The work item that failed
            error: Error message
            retry: If True, re-queue the work item
        """
        work_hash = work_item["hash"]

        async with self.lock:
            # Remove from in_progress
            if work_hash in self.in_progress:
                del self.in_progress[work_hash]

            if retry:
                # Re-queue with lower priority
                agent_type = work_item["agent_type"]
                work_item["priority"] = max(0, work_item.get("priority", 0) - 1)
                work_item["retry_count"] = work_item.get("retry_count", 0) + 1

                # Don't retry more than 3 times
                if work_item["retry_count"] < 3:
                    self.pending[agent_type].append(work_item)
                    logger.info(
                        f"Re-queued failed work item: {work_item['tool']} "
                        f"(retry {work_item['retry_count']})"
                    )
                else:
                    self.failed[work_hash] = {
                        "work_item": work_item,
                        "error": error,
                        "failed_at": datetime.utcnow().isoformat()
                    }
                    logger.warning(
                        f"Work item failed after 3 retries: {work_item['tool']}"
                    )
            else:
                # Mark as failed
                self.failed[work_hash] = {
                    "work_item": work_item,
                    "error": error,
                    "failed_at": datetime.utcnow().isoformat()
                }

                logger.warning(f"Marked failed: {work_item['tool']}: {error}")

    async def get_queue_status(self) -> Dict[str, Any]:
        """
        Get current queue status

        Returns:
            Dictionary with queue statistics
        """
        async with self.lock:
            pending_by_type = {
                agent_type: len(items)
                for agent_type, items in self.pending.items()
            }

            return {
                "total_added": self.total_added,
                "total_completed": self.total_completed,
                "total_failed": len(self.failed),
                "duplicates_prevented": self.duplicates_prevented,
                "pending_by_type": pending_by_type,
                "in_progress_count": len(self.in_progress),
                "efficiency": (
                    self.duplicates_prevented / self.total_added * 100
                    if self.total_added > 0
                    else 0
                )
            }

    async def get_pending_work(self, agent_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get list of pending work items

        Args:
            agent_type: Optional filter by agent type

        Returns:
            List of pending work items
        """
        async with self.lock:
            if agent_type:
                return list(self.pending.get(agent_type, []))
            else:
                # Return all pending work
                all_pending = []
                for items in self.pending.values():
                    all_pending.extend(items)
                return all_pending

    async def get_in_progress_work(self) -> List[Dict[str, Any]]:
        """
        Get list of work items currently in progress

        Returns:
            List of in-progress work items
        """
        async with self.lock:
            return list(self.in_progress.values())

    async def clear(self):
        """Clear all work items from queue"""
        async with self.lock:
            self.pending.clear()
            self.in_progress.clear()
            self.completed.clear()
            self.failed.clear()

            self.total_added = 0
            self.total_completed = 0
            self.duplicates_prevented = 0

            logger.info("Work queue cleared")

    def __repr__(self) -> str:
        total_pending = sum(len(items) for items in self.pending.values())
        return (
            f"<WorkQueue pending={total_pending} "
            f"in_progress={len(self.in_progress)} "
            f"completed={len(self.completed)} "
            f"failed={len(self.failed)}>"
        )
