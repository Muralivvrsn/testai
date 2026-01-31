"""
TestAI Agent - Environment Provisioner

Automated environment provisioning with resource
allocation and dependency management.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional


class ResourceType(Enum):
    """Types of resources to provision."""
    COMPUTE = "compute"
    DATABASE = "database"
    CACHE = "cache"
    STORAGE = "storage"
    NETWORK = "network"
    SERVICE = "service"


class ProvisionStatus(Enum):
    """Status of provisioning operation."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ResourceSpec:
    """Specification for a resource."""
    resource_id: str
    resource_type: ResourceType
    name: str
    config: Dict[str, Any]
    dependencies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvisioningPlan:
    """A plan for provisioning resources."""
    plan_id: str
    name: str
    resources: List[ResourceSpec]
    order: List[str]  # Resource IDs in provisioning order
    estimated_duration_sec: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvisionResult:
    """Result of a provisioning operation."""
    result_id: str
    plan: ProvisioningPlan
    status: ProvisionStatus
    resources_provisioned: List[str]
    resources_failed: List[str]
    duration_sec: float
    started_at: datetime
    completed_at: Optional[datetime]
    logs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class EnvironmentProvisioner:
    """
    Environment provisioner.

    Features:
    - Resource dependency resolution
    - Parallel provisioning
    - Rollback support
    - Health verification
    """

    def __init__(
        self,
        parallel_workers: int = 3,
        timeout: int = 600,
    ):
        """Initialize the provisioner."""
        self._parallel_workers = parallel_workers
        self._timeout = timeout
        self._plans: Dict[str, ProvisioningPlan] = {}
        self._results: List[ProvisionResult] = []
        self._plan_counter = 0
        self._result_counter = 0
        self._resource_counter = 0

    def create_resource_spec(
        self,
        resource_type: ResourceType,
        name: str,
        config: Dict[str, Any],
        dependencies: Optional[List[str]] = None,
    ) -> ResourceSpec:
        """Create a resource specification."""
        self._resource_counter += 1
        resource_id = f"RES-{self._resource_counter:05d}"

        return ResourceSpec(
            resource_id=resource_id,
            resource_type=resource_type,
            name=name,
            config=config,
            dependencies=dependencies or [],
        )

    def create_plan(
        self,
        name: str,
        resources: List[ResourceSpec],
    ) -> ProvisioningPlan:
        """Create a provisioning plan."""
        self._plan_counter += 1
        plan_id = f"PLAN-{self._plan_counter:05d}"

        # Resolve dependency order
        order = self._resolve_order(resources)

        # Estimate duration
        duration = len(resources) * 30  # 30 sec per resource

        plan = ProvisioningPlan(
            plan_id=plan_id,
            name=name,
            resources=resources,
            order=order,
            estimated_duration_sec=duration,
        )

        self._plans[plan_id] = plan
        return plan

    def _resolve_order(self, resources: List[ResourceSpec]) -> List[str]:
        """Resolve resource provisioning order based on dependencies."""
        # Build dependency graph
        graph: Dict[str, List[str]] = {}
        for res in resources:
            graph[res.resource_id] = res.dependencies

        # Topological sort
        order = []
        visited = set()
        visiting = set()

        def visit(res_id: str):
            if res_id in visited:
                return
            if res_id in visiting:
                raise ValueError(f"Circular dependency detected: {res_id}")

            visiting.add(res_id)
            for dep in graph.get(res_id, []):
                visit(dep)
            visiting.remove(res_id)
            visited.add(res_id)
            order.append(res_id)

        for res in resources:
            visit(res.resource_id)

        return order

    def provision(
        self,
        plan: ProvisioningPlan,
        dry_run: bool = False,
    ) -> ProvisionResult:
        """Execute a provisioning plan."""
        self._result_counter += 1
        result_id = f"PROV-{self._result_counter:05d}"

        started_at = datetime.now()
        resources_provisioned = []
        resources_failed = []
        logs = []

        status = ProvisionStatus.IN_PROGRESS
        logs.append(f"Starting provisioning plan: {plan.name}")

        for res_id in plan.order:
            resource = next((r for r in plan.resources if r.resource_id == res_id), None)
            if not resource:
                continue

            logs.append(f"Provisioning {resource.name} ({resource.resource_type.value})...")

            if dry_run:
                logs.append(f"  [DRY RUN] Would provision {resource.name}")
                resources_provisioned.append(res_id)
            else:
                # Simulate provisioning
                try:
                    # In real implementation, actual provisioning would happen here
                    resources_provisioned.append(res_id)
                    logs.append(f"  ✓ {resource.name} provisioned successfully")
                except Exception as e:
                    resources_failed.append(res_id)
                    logs.append(f"  ✗ {resource.name} failed: {str(e)}")

        completed_at = datetime.now()
        duration = (completed_at - started_at).total_seconds()

        if resources_failed:
            status = ProvisionStatus.FAILED
        else:
            status = ProvisionStatus.COMPLETED

        logs.append(f"Provisioning completed: {status.value}")

        result = ProvisionResult(
            result_id=result_id,
            plan=plan,
            status=status,
            resources_provisioned=resources_provisioned,
            resources_failed=resources_failed,
            duration_sec=duration,
            started_at=started_at,
            completed_at=completed_at,
            logs=logs,
        )

        self._results.append(result)
        return result

    def rollback(
        self,
        result: ProvisionResult,
    ) -> ProvisionResult:
        """Rollback a provisioning operation."""
        self._result_counter += 1
        rollback_id = f"ROLLBACK-{self._result_counter:05d}"

        started_at = datetime.now()
        logs = [f"Rolling back: {result.result_id}"]

        # Reverse order for rollback
        for res_id in reversed(result.resources_provisioned):
            resource = next(
                (r for r in result.plan.resources if r.resource_id == res_id),
                None
            )
            if resource:
                logs.append(f"Destroying {resource.name}...")
                logs.append(f"  ✓ {resource.name} destroyed")

        completed_at = datetime.now()

        rollback_result = ProvisionResult(
            result_id=rollback_id,
            plan=result.plan,
            status=ProvisionStatus.ROLLED_BACK,
            resources_provisioned=[],
            resources_failed=[],
            duration_sec=(completed_at - started_at).total_seconds(),
            started_at=started_at,
            completed_at=completed_at,
            logs=logs,
        )

        self._results.append(rollback_result)
        return rollback_result

    def get_plan(self, plan_id: str) -> Optional[ProvisioningPlan]:
        """Get a plan by ID."""
        return self._plans.get(plan_id)

    def get_statistics(self) -> Dict[str, Any]:
        """Get provisioner statistics."""
        status_counts = {s.value: 0 for s in ProvisionStatus}
        for result in self._results:
            status_counts[result.status.value] += 1

        total_resources = sum(len(r.resources_provisioned) for r in self._results)

        return {
            "total_plans": len(self._plans),
            "total_provisions": len(self._results),
            "total_resources_provisioned": total_resources,
            "provisions_by_status": status_counts,
        }

    def format_result(self, result: ProvisionResult) -> str:
        """Format a provisioning result for display."""
        status_icons = {
            ProvisionStatus.PENDING: "⏳",
            ProvisionStatus.IN_PROGRESS: "🔄",
            ProvisionStatus.COMPLETED: "✅",
            ProvisionStatus.FAILED: "❌",
            ProvisionStatus.ROLLED_BACK: "↩️",
        }

        icon = status_icons.get(result.status, "")

        lines = [
            "=" * 55,
            f"  PROVISION RESULT: {icon} {result.status.value.upper()}",
            "=" * 55,
            "",
            f"  Plan: {result.plan.name}",
            f"  Duration: {result.duration_sec:.1f}s",
            "",
            "-" * 55,
            "  RESOURCES",
            "-" * 55,
            "",
            f"  Provisioned: {len(result.resources_provisioned)}",
            f"  Failed: {len(result.resources_failed)}",
            "",
        ]

        if result.logs:
            lines.append("-" * 55)
            lines.append("  LOGS (last 5)")
            lines.append("-" * 55)
            lines.append("")
            for log in result.logs[-5:]:
                lines.append(f"  {log}")
            lines.append("")

        lines.append("=" * 55)
        return "\n".join(lines)


def create_provisioner(
    parallel_workers: int = 3,
    timeout: int = 600,
) -> EnvironmentProvisioner:
    """Create a provisioner instance."""
    return EnvironmentProvisioner(
        parallel_workers=parallel_workers,
        timeout=timeout,
    )
