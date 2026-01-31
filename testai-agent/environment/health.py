"""
TestAI Agent - Health Checker

Monitors the health of test environments and their
dependent services.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import time


class HealthStatus(Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class ServiceHealth:
    """Health status of a service."""
    service_name: str
    url: str
    status: HealthStatus
    response_time_ms: int
    last_check: datetime
    consecutive_failures: int = 0
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    check_id: str
    service_name: str
    passed: bool
    status: HealthStatus
    response_time_ms: int
    timestamp: datetime
    message: str


@dataclass
class HealthReport:
    """Complete health report."""
    total_services: int
    healthy: int
    warning: int
    critical: int
    overall_status: HealthStatus
    services: List[ServiceHealth]
    recommendations: List[str]


class HealthChecker:
    """
    Monitors service health.

    Features:
    - Service health checks
    - Threshold-based alerting
    - Historical tracking
    - Recommendations
    """

    # Health thresholds
    THRESHOLDS = {
        "response_time_warning_ms": 2000,
        "response_time_critical_ms": 5000,
        "consecutive_failures_warning": 2,
        "consecutive_failures_critical": 5,
    }

    def __init__(self):
        """Initialize the health checker."""
        self._services: Dict[str, ServiceHealth] = {}
        self._check_history: Dict[str, List[HealthCheckResult]] = {}
        self._check_counter = 0
        self._check_functions: Dict[str, Callable] = {}

    def register_service(
        self,
        service_name: str,
        url: str,
        check_function: Optional[Callable] = None,
    ):
        """Register a service for health monitoring."""
        self._services[service_name] = ServiceHealth(
            service_name=service_name,
            url=url,
            status=HealthStatus.UNKNOWN,
            response_time_ms=0,
            last_check=datetime.now(),
        )

        if check_function:
            self._check_functions[service_name] = check_function

        self._check_history[service_name] = []

    def check_service(
        self,
        service_name: str,
        simulate_response_ms: Optional[int] = None,
        simulate_failure: bool = False,
    ) -> HealthCheckResult:
        """Check the health of a service."""
        self._check_counter += 1

        service = self._services.get(service_name)
        if not service:
            return HealthCheckResult(
                check_id=f"CHK-{self._check_counter:05d}",
                service_name=service_name,
                passed=False,
                status=HealthStatus.UNKNOWN,
                response_time_ms=0,
                timestamp=datetime.now(),
                message="Service not registered",
            )

        # Simulate or perform actual check
        if simulate_response_ms is not None or simulate_failure:
            response_time = simulate_response_ms or 0
            success = not simulate_failure
            error_msg = "Simulated failure" if simulate_failure else None
        else:
            # Check if we have a custom check function
            if service_name in self._check_functions:
                try:
                    start = time.time()
                    result = self._check_functions[service_name](service.url)
                    response_time = int((time.time() - start) * 1000)
                    success = bool(result)
                    error_msg = None if success else "Check returned False"
                except Exception as e:
                    response_time = 0
                    success = False
                    error_msg = str(e)
            else:
                # Simulate a successful check
                response_time = 100
                success = True
                error_msg = None

        # Determine status
        status = self._calculate_status(response_time, success, service)

        # Update service
        if success:
            service.consecutive_failures = 0
        else:
            service.consecutive_failures += 1

        service.status = status
        service.response_time_ms = response_time
        service.last_check = datetime.now()
        service.error_message = error_msg

        # Create result
        result = HealthCheckResult(
            check_id=f"CHK-{self._check_counter:05d}",
            service_name=service_name,
            passed=success,
            status=status,
            response_time_ms=response_time,
            timestamp=datetime.now(),
            message=error_msg or f"Response time: {response_time}ms",
        )

        # Store in history
        self._check_history[service_name].append(result)

        # Keep only last 100 results
        if len(self._check_history[service_name]) > 100:
            self._check_history[service_name] = self._check_history[service_name][-100:]

        return result

    def _calculate_status(
        self,
        response_time: int,
        success: bool,
        service: ServiceHealth,
    ) -> HealthStatus:
        """Calculate health status based on metrics."""
        if not success:
            failures = service.consecutive_failures + 1

            if failures >= self.THRESHOLDS["consecutive_failures_critical"]:
                return HealthStatus.CRITICAL
            elif failures >= self.THRESHOLDS["consecutive_failures_warning"]:
                return HealthStatus.WARNING
            return HealthStatus.WARNING

        if response_time >= self.THRESHOLDS["response_time_critical_ms"]:
            return HealthStatus.CRITICAL
        elif response_time >= self.THRESHOLDS["response_time_warning_ms"]:
            return HealthStatus.WARNING

        return HealthStatus.HEALTHY

    def check_all_services(self) -> List[HealthCheckResult]:
        """Check health of all registered services."""
        results = []
        for service_name in self._services:
            result = self.check_service(service_name)
            results.append(result)
        return results

    def get_service_health(self, service_name: str) -> Optional[ServiceHealth]:
        """Get current health of a service."""
        return self._services.get(service_name)

    def get_service_history(
        self,
        service_name: str,
        limit: int = 10,
    ) -> List[HealthCheckResult]:
        """Get health check history for a service."""
        history = self._check_history.get(service_name, [])
        return history[-limit:]

    def get_service_uptime(
        self,
        service_name: str,
        hours: int = 24,
    ) -> float:
        """Calculate service uptime percentage."""
        history = self._check_history.get(service_name, [])

        if not history:
            return 1.0

        cutoff = datetime.now() - timedelta(hours=hours)
        recent = [r for r in history if r.timestamp >= cutoff]

        if not recent:
            return 1.0

        successful = sum(1 for r in recent if r.passed)
        return successful / len(recent)

    def get_average_response_time(
        self,
        service_name: str,
        limit: int = 10,
    ) -> float:
        """Get average response time for a service."""
        history = self._check_history.get(service_name, [])

        if not history:
            return 0.0

        recent = history[-limit:]
        successful = [r for r in recent if r.passed]

        if not successful:
            return 0.0

        return sum(r.response_time_ms for r in successful) / len(successful)

    def generate_report(self) -> HealthReport:
        """Generate a health report."""
        services = list(self._services.values())

        healthy = sum(1 for s in services if s.status == HealthStatus.HEALTHY)
        warning = sum(1 for s in services if s.status == HealthStatus.WARNING)
        critical = sum(1 for s in services if s.status == HealthStatus.CRITICAL)

        # Calculate overall status
        if critical > 0:
            overall = HealthStatus.CRITICAL
        elif warning > 0:
            overall = HealthStatus.WARNING
        elif healthy == len(services) and services:
            overall = HealthStatus.HEALTHY
        else:
            overall = HealthStatus.UNKNOWN

        # Generate recommendations
        recommendations = self._generate_recommendations(services)

        return HealthReport(
            total_services=len(services),
            healthy=healthy,
            warning=warning,
            critical=critical,
            overall_status=overall,
            services=services,
            recommendations=recommendations,
        )

    def _generate_recommendations(
        self,
        services: List[ServiceHealth],
    ) -> List[str]:
        """Generate recommendations based on service health."""
        recommendations = []

        for service in services:
            if service.status == HealthStatus.CRITICAL:
                recommendations.append(
                    f"CRITICAL: {service.service_name} requires immediate attention"
                )

            if service.consecutive_failures > 0:
                recommendations.append(
                    f"Investigate {service.service_name} - {service.consecutive_failures} consecutive failures"
                )

            if service.response_time_ms > self.THRESHOLDS["response_time_warning_ms"]:
                recommendations.append(
                    f"Optimize {service.service_name} - response time {service.response_time_ms}ms exceeds threshold"
                )

            # Check uptime
            uptime = self.get_service_uptime(service.service_name, hours=24)
            if uptime < 0.95:
                recommendations.append(
                    f"Improve {service.service_name} reliability - 24h uptime is {uptime:.1%}"
                )

        return recommendations[:10]  # Limit recommendations

    def set_threshold(self, key: str, value: int):
        """Set a health threshold."""
        if key in self.THRESHOLDS:
            self.THRESHOLDS[key] = value

    def format_report(self, report: HealthReport) -> str:
        """Format health report as readable text."""
        lines = [
            "=" * 60,
            "  SERVICE HEALTH REPORT",
            "=" * 60,
            "",
            f"  Total Services: {report.total_services}",
            f"  Healthy: {report.healthy}",
            f"  Warning: {report.warning}",
            f"  Critical: {report.critical}",
            "",
            f"  Overall Status: {report.overall_status.value.upper()}",
            "",
        ]

        if report.services:
            lines.extend([
                "-" * 60,
                "  SERVICES",
                "-" * 60,
            ])

            for service in report.services:
                status_icon = {
                    HealthStatus.HEALTHY: "✅",
                    HealthStatus.WARNING: "⚠️",
                    HealthStatus.CRITICAL: "❌",
                }.get(service.status, "❓")

                lines.extend([
                    "",
                    f"  {status_icon} {service.service_name}",
                    f"     URL: {service.url}",
                    f"     Status: {service.status.value}",
                    f"     Response Time: {service.response_time_ms}ms",
                    f"     Last Check: {service.last_check.strftime('%Y-%m-%d %H:%M:%S')}",
                ])

                if service.error_message:
                    lines.append(f"     Error: {service.error_message}")

        if report.recommendations:
            lines.extend([
                "",
                "-" * 60,
                "  RECOMMENDATIONS",
                "-" * 60,
            ])
            for rec in report.recommendations:
                lines.append(f"  • {rec}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_health_checker() -> HealthChecker:
    """Create a health checker instance."""
    return HealthChecker()
