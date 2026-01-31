"""
TestAI Agent - Test Distributor

Distributes test execution across worker nodes
with intelligent load balancing.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import uuid


class DistributionStrategy(Enum):
    """Distribution strategies."""
    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    CAPABILITY_BASED = "capability_based"
    AFFINITY = "affinity"
    RANDOM = "random"


class WorkerStatus(Enum):
    """Worker node status."""
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    DRAINING = "draining"
    ERROR = "error"


@dataclass
class WorkerCapabilities:
    """Capabilities of a worker node."""
    browsers: List[str]
    devices: List[str]
    max_parallel: int
    tags: List[str] = field(default_factory=list)


@dataclass
class WorkerNode:
    """A worker node for test execution."""
    node_id: str
    name: str
    status: WorkerStatus
    capabilities: WorkerCapabilities
    current_load: int
    max_load: int
    last_heartbeat: datetime
    assigned_runs: Set[str] = field(default_factory=set)
    completed_runs: int = 0
    failed_runs: int = 0
    avg_execution_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_available(self) -> bool:
        return self.status == WorkerStatus.ONLINE and self.current_load < self.max_load

    @property
    def load_percentage(self) -> float:
        return self.current_load / self.max_load if self.max_load > 0 else 1.0


@dataclass
class DistributionResult:
    """Result of test distribution."""
    run_id: str
    node_id: str
    test_ids: List[str]
    browser: str
    device: str
    distributed_at: datetime = field(default_factory=datetime.now)


class TestDistributor:
    """
    Distributes tests across worker nodes.

    Features:
    - Multiple distribution strategies
    - Capability matching
    - Load balancing
    - Worker health monitoring
    """

    def __init__(self, strategy: DistributionStrategy = DistributionStrategy.LEAST_LOADED):
        """Initialize the distributor."""
        self.strategy = strategy
        self._nodes: Dict[str, WorkerNode] = {}
        self._distributions: Dict[str, DistributionResult] = {}
        self._affinity_map: Dict[str, str] = {}  # test_id -> preferred_node_id
        self._round_robin_index = 0

    def register_node(
        self,
        name: str,
        capabilities: WorkerCapabilities,
        max_load: int = 5,
    ) -> WorkerNode:
        """Register a worker node."""
        node_id = f"node-{len(self._nodes) + 1:03d}-{uuid.uuid4().hex[:6]}"

        node = WorkerNode(
            node_id=node_id,
            name=name,
            status=WorkerStatus.ONLINE,
            capabilities=capabilities,
            current_load=0,
            max_load=max_load,
            last_heartbeat=datetime.now(),
        )

        self._nodes[node_id] = node
        return node

    def unregister_node(self, node_id: str) -> bool:
        """Unregister a worker node."""
        if node_id in self._nodes:
            del self._nodes[node_id]
            return True
        return False

    def update_node_status(self, node_id: str, status: WorkerStatus) -> bool:
        """Update worker node status."""
        node = self._nodes.get(node_id)
        if not node:
            return False

        node.status = status
        node.last_heartbeat = datetime.now()
        return True

    def heartbeat(self, node_id: str) -> bool:
        """Record heartbeat from a node."""
        node = self._nodes.get(node_id)
        if not node:
            return False

        node.last_heartbeat = datetime.now()
        return True

    def distribute(
        self,
        run_id: str,
        test_ids: List[str],
        browser: str,
        device: str,
        tags: Optional[List[str]] = None,
    ) -> Optional[DistributionResult]:
        """Distribute a test run to a worker."""
        # Find suitable nodes
        suitable = self._find_suitable_nodes(browser, device, tags or [])

        if not suitable:
            return None

        # Select node based on strategy
        selected = self._select_node(suitable, test_ids)

        if not selected:
            return None

        # Create distribution
        result = DistributionResult(
            run_id=run_id,
            node_id=selected.node_id,
            test_ids=test_ids,
            browser=browser,
            device=device,
        )

        # Update node
        selected.current_load += 1
        selected.assigned_runs.add(run_id)

        self._distributions[run_id] = result
        return result

    def _find_suitable_nodes(
        self,
        browser: str,
        device: str,
        tags: List[str],
    ) -> List[WorkerNode]:
        """Find nodes capable of running the test."""
        suitable = []

        for node in self._nodes.values():
            if not node.is_available:
                continue

            # Check browser capability
            if browser not in node.capabilities.browsers:
                continue

            # Check device capability
            if device not in node.capabilities.devices:
                continue

            # Check tags if specified
            if tags and not all(t in node.capabilities.tags for t in tags):
                continue

            suitable.append(node)

        return suitable

    def _select_node(
        self,
        nodes: List[WorkerNode],
        test_ids: List[str],
    ) -> Optional[WorkerNode]:
        """Select a node based on distribution strategy."""
        if not nodes:
            return None

        if self.strategy == DistributionStrategy.ROUND_ROBIN:
            return self._select_round_robin(nodes)
        elif self.strategy == DistributionStrategy.LEAST_LOADED:
            return self._select_least_loaded(nodes)
        elif self.strategy == DistributionStrategy.AFFINITY:
            return self._select_affinity(nodes, test_ids)
        elif self.strategy == DistributionStrategy.CAPABILITY_BASED:
            return self._select_capability_based(nodes)
        else:
            return nodes[0] if nodes else None

    def _select_round_robin(self, nodes: List[WorkerNode]) -> WorkerNode:
        """Select node using round robin."""
        node = nodes[self._round_robin_index % len(nodes)]
        self._round_robin_index += 1
        return node

    def _select_least_loaded(self, nodes: List[WorkerNode]) -> WorkerNode:
        """Select the least loaded node."""
        return min(nodes, key=lambda n: n.load_percentage)

    def _select_affinity(
        self,
        nodes: List[WorkerNode],
        test_ids: List[str],
    ) -> WorkerNode:
        """Select node based on affinity."""
        # Check if any test has affinity
        for test_id in test_ids:
            if test_id in self._affinity_map:
                preferred = self._affinity_map[test_id]
                for node in nodes:
                    if node.node_id == preferred:
                        return node

        # Fall back to least loaded
        return self._select_least_loaded(nodes)

    def _select_capability_based(self, nodes: List[WorkerNode]) -> WorkerNode:
        """Select based on best capability match."""
        # Prefer nodes with fewer capabilities (specialized)
        return min(
            nodes,
            key=lambda n: len(n.capabilities.browsers) + len(n.capabilities.devices),
        )

    def set_affinity(self, test_id: str, node_id: str):
        """Set node affinity for a test."""
        self._affinity_map[test_id] = node_id

    def complete_run(
        self,
        run_id: str,
        success: bool = True,
        execution_time_ms: int = 0,
    ) -> bool:
        """Mark a distributed run as complete."""
        distribution = self._distributions.get(run_id)
        if not distribution:
            return False

        node = self._nodes.get(distribution.node_id)
        if node:
            node.current_load = max(0, node.current_load - 1)
            node.assigned_runs.discard(run_id)

            if success:
                node.completed_runs += 1
            else:
                node.failed_runs += 1

            # Update average execution time
            total_runs = node.completed_runs + node.failed_runs
            if total_runs > 0:
                node.avg_execution_time_ms = (
                    (node.avg_execution_time_ms * (total_runs - 1) + execution_time_ms)
                    / total_runs
                )

            # Update affinity for successful runs
            if success:
                for test_id in distribution.test_ids:
                    self._affinity_map[test_id] = node.node_id

        return True

    def get_node(self, node_id: str) -> Optional[WorkerNode]:
        """Get a worker node by ID."""
        return self._nodes.get(node_id)

    def get_nodes(self, status: Optional[WorkerStatus] = None) -> List[WorkerNode]:
        """Get all worker nodes, optionally filtered by status."""
        nodes = list(self._nodes.values())
        if status:
            nodes = [n for n in nodes if n.status == status]
        return nodes

    def get_distribution(self, run_id: str) -> Optional[DistributionResult]:
        """Get distribution for a run."""
        return self._distributions.get(run_id)

    def get_statistics(self) -> Dict[str, Any]:
        """Get distributor statistics."""
        nodes = list(self._nodes.values())
        online = [n for n in nodes if n.status == WorkerStatus.ONLINE]

        total_capacity = sum(n.max_load for n in online)
        total_load = sum(n.current_load for n in online)

        return {
            "total_nodes": len(nodes),
            "online_nodes": len(online),
            "total_capacity": total_capacity,
            "current_load": total_load,
            "utilization": total_load / total_capacity if total_capacity > 0 else 0,
            "total_distributions": len(self._distributions),
            "strategy": self.strategy.value,
        }

    def rebalance(self) -> List[DistributionResult]:
        """Rebalance distributions across nodes."""
        # Find overloaded and underloaded nodes
        online = [n for n in self._nodes.values() if n.status == WorkerStatus.ONLINE]

        if len(online) < 2:
            return []

        avg_load = sum(n.current_load for n in online) / len(online)
        overloaded = [n for n in online if n.current_load > avg_load + 1]
        underloaded = [n for n in online if n.current_load < avg_load - 1]

        rebalanced = []

        for over in overloaded:
            for under in underloaded:
                if over.current_load <= under.current_load + 1:
                    break

                # Find a run to move
                for run_id in list(over.assigned_runs)[:1]:
                    dist = self._distributions.get(run_id)
                    if not dist:
                        continue

                    # Check capability
                    if (dist.browser not in under.capabilities.browsers or
                            dist.device not in under.capabilities.devices):
                        continue

                    # Move run
                    over.assigned_runs.discard(run_id)
                    over.current_load -= 1
                    under.assigned_runs.add(run_id)
                    under.current_load += 1

                    # Update distribution
                    new_dist = DistributionResult(
                        run_id=run_id,
                        node_id=under.node_id,
                        test_ids=dist.test_ids,
                        browser=dist.browser,
                        device=dist.device,
                    )
                    self._distributions[run_id] = new_dist
                    rebalanced.append(new_dist)

        return rebalanced

    def format_status(self) -> str:
        """Format distributor status."""
        stats = self.get_statistics()

        lines = [
            "=" * 60,
            "  TEST DISTRIBUTOR STATUS",
            "=" * 60,
            "",
            f"  Strategy: {stats['strategy']}",
            f"  Nodes: {stats['online_nodes']}/{stats['total_nodes']} online",
            f"  Load: {stats['current_load']}/{stats['total_capacity']}",
            f"  Utilization: {stats['utilization']:.1%}",
            "",
        ]

        if self._nodes:
            lines.extend(["-" * 60, "  WORKER NODES", "-" * 60])

            for node in self._nodes.values():
                status_icon = {
                    WorkerStatus.ONLINE: "🟢",
                    WorkerStatus.OFFLINE: "🔴",
                    WorkerStatus.BUSY: "🟡",
                    WorkerStatus.DRAINING: "🟠",
                    WorkerStatus.ERROR: "❌",
                }.get(node.status, "⚪")

                lines.extend([
                    "",
                    f"  {status_icon} {node.name} ({node.node_id})",
                    f"     Load: {node.current_load}/{node.max_load}",
                    f"     Browsers: {', '.join(node.capabilities.browsers)}",
                    f"     Completed: {node.completed_runs} | Failed: {node.failed_runs}",
                ])

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_distributor(
    strategy: DistributionStrategy = DistributionStrategy.LEAST_LOADED,
) -> TestDistributor:
    """Create a test distributor instance."""
    return TestDistributor(strategy)
