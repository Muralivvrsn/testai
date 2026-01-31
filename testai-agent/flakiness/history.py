"""
TestAI Agent - Execution History

Tracks historical test execution data for flakiness
analysis and trend detection.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import statistics


@dataclass
class ExecutionRecord:
    """A single test execution record."""
    test_id: str
    run_id: str
    timestamp: datetime
    passed: bool
    duration_ms: int
    error_message: Optional[str] = None
    retry_count: int = 0
    environment: str = "default"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestHistory:
    """Historical data for a single test."""
    test_id: str
    executions: List[ExecutionRecord]
    total_runs: int = 0
    total_passes: int = 0
    total_failures: int = 0
    pass_rate: float = 0.0
    avg_duration_ms: float = 0.0
    duration_variance: float = 0.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class ExecutionHistory:
    """
    Manages historical execution data for tests.

    Provides:
    - Recording of test executions
    - Statistical aggregation
    - Time-series analysis
    - Environment-based filtering
    """

    def __init__(
        self,
        max_records_per_test: int = 100,
        retention_days: int = 30,
    ):
        """Initialize the execution history."""
        self.max_records_per_test = max_records_per_test
        self.retention_days = retention_days
        self._records: Dict[str, List[ExecutionRecord]] = {}
        self._run_ids: Set[str] = set()

    def record(
        self,
        test_id: str,
        run_id: str,
        passed: bool,
        duration_ms: int,
        error_message: Optional[str] = None,
        retry_count: int = 0,
        environment: str = "default",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Record a test execution."""
        record = ExecutionRecord(
            test_id=test_id,
            run_id=run_id,
            timestamp=datetime.now(),
            passed=passed,
            duration_ms=duration_ms,
            error_message=error_message,
            retry_count=retry_count,
            environment=environment,
            metadata=metadata or {},
        )

        if test_id not in self._records:
            self._records[test_id] = []

        self._records[test_id].append(record)
        self._run_ids.add(run_id)

        # Enforce max records limit
        if len(self._records[test_id]) > self.max_records_per_test:
            self._records[test_id] = self._records[test_id][-self.max_records_per_test:]

    def record_batch(
        self,
        run_id: str,
        results: List[Dict[str, Any]],
        environment: str = "default",
    ):
        """Record a batch of test results from a single run."""
        for result in results:
            self.record(
                test_id=result.get("test_id", ""),
                run_id=run_id,
                passed=result.get("passed", False),
                duration_ms=result.get("duration_ms", 0),
                error_message=result.get("error"),
                retry_count=result.get("retries", 0),
                environment=environment,
                metadata=result.get("metadata"),
            )

    def get_test_history(
        self,
        test_id: str,
        since: Optional[datetime] = None,
        environment: Optional[str] = None,
    ) -> TestHistory:
        """Get historical data for a test."""
        records = self._records.get(test_id, [])

        # Filter by time
        if since:
            records = [r for r in records if r.timestamp >= since]

        # Filter by environment
        if environment:
            records = [r for r in records if r.environment == environment]

        if not records:
            return TestHistory(
                test_id=test_id,
                executions=[],
                total_runs=0,
                total_passes=0,
                total_failures=0,
                pass_rate=0.0,
            )

        # Calculate statistics
        passes = sum(1 for r in records if r.passed)
        failures = len(records) - passes
        durations = [r.duration_ms for r in records]

        avg_duration = statistics.mean(durations) if durations else 0
        duration_var = statistics.variance(durations) if len(durations) > 1 else 0

        return TestHistory(
            test_id=test_id,
            executions=records,
            total_runs=len(records),
            total_passes=passes,
            total_failures=failures,
            pass_rate=passes / len(records) if records else 0,
            avg_duration_ms=avg_duration,
            duration_variance=duration_var,
            first_seen=min(r.timestamp for r in records),
            last_seen=max(r.timestamp for r in records),
        )

    def get_all_test_ids(self) -> List[str]:
        """Get all test IDs with history."""
        return list(self._records.keys())

    def get_run_ids(self, limit: int = 10) -> List[str]:
        """Get recent run IDs."""
        return list(self._run_ids)[-limit:]

    def get_run_results(
        self,
        run_id: str,
    ) -> List[ExecutionRecord]:
        """Get all results for a specific run."""
        results = []
        for records in self._records.values():
            for record in records:
                if record.run_id == run_id:
                    results.append(record)
        return results

    def get_recent_failures(
        self,
        limit: int = 10,
    ) -> List[ExecutionRecord]:
        """Get recent failures across all tests."""
        all_failures = []
        for records in self._records.values():
            failures = [r for r in records if not r.passed]
            all_failures.extend(failures)

        # Sort by timestamp descending
        all_failures.sort(key=lambda x: x.timestamp, reverse=True)
        return all_failures[:limit]

    def get_pass_rate_trend(
        self,
        test_id: str,
        window_size: int = 10,
    ) -> List[float]:
        """Get pass rate trend over sliding windows."""
        records = self._records.get(test_id, [])
        if len(records) < window_size:
            return [self.get_test_history(test_id).pass_rate]

        # Sort by timestamp
        records = sorted(records, key=lambda x: x.timestamp)

        trends = []
        for i in range(len(records) - window_size + 1):
            window = records[i:i + window_size]
            pass_rate = sum(1 for r in window if r.passed) / len(window)
            trends.append(pass_rate)

        return trends

    def get_duration_trend(
        self,
        test_id: str,
        window_size: int = 10,
    ) -> List[float]:
        """Get duration trend over sliding windows."""
        records = self._records.get(test_id, [])
        if len(records) < window_size:
            history = self.get_test_history(test_id)
            return [history.avg_duration_ms]

        records = sorted(records, key=lambda x: x.timestamp)

        trends = []
        for i in range(len(records) - window_size + 1):
            window = records[i:i + window_size]
            avg_duration = statistics.mean(r.duration_ms for r in window)
            trends.append(avg_duration)

        return trends

    def get_failure_patterns(
        self,
        test_id: str,
    ) -> Dict[str, int]:
        """Get failure patterns (error message grouping)."""
        records = self._records.get(test_id, [])
        failures = [r for r in records if not r.passed and r.error_message]

        patterns: Dict[str, int] = {}
        for failure in failures:
            # Normalize error message for grouping
            error_key = self._normalize_error(failure.error_message or "")
            patterns[error_key] = patterns.get(error_key, 0) + 1

        return patterns

    def get_environment_comparison(
        self,
        test_id: str,
    ) -> Dict[str, Dict[str, Any]]:
        """Compare test performance across environments."""
        records = self._records.get(test_id, [])

        by_env: Dict[str, List[ExecutionRecord]] = {}
        for record in records:
            if record.environment not in by_env:
                by_env[record.environment] = []
            by_env[record.environment].append(record)

        comparison = {}
        for env, env_records in by_env.items():
            passes = sum(1 for r in env_records if r.passed)
            durations = [r.duration_ms for r in env_records]

            comparison[env] = {
                "total_runs": len(env_records),
                "pass_rate": passes / len(env_records) if env_records else 0,
                "avg_duration_ms": statistics.mean(durations) if durations else 0,
            }

        return comparison

    def cleanup_old_records(self):
        """Remove records older than retention period."""
        cutoff = datetime.now() - timedelta(days=self.retention_days)

        for test_id in self._records:
            self._records[test_id] = [
                r for r in self._records[test_id]
                if r.timestamp >= cutoff
            ]

    def export(self) -> Dict[str, Any]:
        """Export all history data."""
        return {
            "tests": {
                test_id: [
                    {
                        "run_id": r.run_id,
                        "timestamp": r.timestamp.isoformat(),
                        "passed": r.passed,
                        "duration_ms": r.duration_ms,
                        "error_message": r.error_message,
                        "retry_count": r.retry_count,
                        "environment": r.environment,
                    }
                    for r in records
                ]
                for test_id, records in self._records.items()
            },
            "run_ids": list(self._run_ids),
            "exported_at": datetime.now().isoformat(),
        }

    def import_data(self, data: Dict[str, Any]):
        """Import history data."""
        for test_id, records in data.get("tests", {}).items():
            for r in records:
                self.record(
                    test_id=test_id,
                    run_id=r.get("run_id", ""),
                    passed=r.get("passed", False),
                    duration_ms=r.get("duration_ms", 0),
                    error_message=r.get("error_message"),
                    retry_count=r.get("retry_count", 0),
                    environment=r.get("environment", "default"),
                )

    def _normalize_error(self, error: str) -> str:
        """Normalize error message for pattern matching."""
        # Remove specific values but keep structure
        import re

        # Remove line numbers
        error = re.sub(r"line \d+", "line X", error)
        # Remove file paths
        error = re.sub(r"/[^\s]+", "<path>", error)
        # Remove memory addresses
        error = re.sub(r"0x[0-9a-fA-F]+", "0x...", error)
        # Remove timestamps
        error = re.sub(r"\d{4}-\d{2}-\d{2}", "YYYY-MM-DD", error)
        # Truncate
        return error[:100]

    def format_history(self, history: TestHistory) -> str:
        """Format test history as readable text."""
        lines = [
            "-" * 50,
            f"  TEST HISTORY: {history.test_id}",
            "-" * 50,
            "",
            f"  Total Runs: {history.total_runs}",
            f"  Pass Rate: {history.pass_rate:.1%}",
            f"  Passed: {history.total_passes} | Failed: {history.total_failures}",
            "",
            f"  Avg Duration: {history.avg_duration_ms:.0f}ms",
            f"  Duration Variance: {history.duration_variance:.0f}",
            "",
        ]

        if history.first_seen:
            lines.append(f"  First Seen: {history.first_seen.strftime('%Y-%m-%d %H:%M')}")
        if history.last_seen:
            lines.append(f"  Last Seen: {history.last_seen.strftime('%Y-%m-%d %H:%M')}")

        # Recent results
        if history.executions:
            lines.extend([
                "",
                "  Recent Results:",
            ])
            for record in history.executions[-5:]:
                icon = "✅" if record.passed else "❌"
                time_str = record.timestamp.strftime("%m/%d %H:%M")
                lines.append(f"    {icon} {time_str} ({record.duration_ms}ms)")

        lines.append("-" * 50)
        return "\n".join(lines)


def create_execution_history(
    max_records_per_test: int = 100,
    retention_days: int = 30,
) -> ExecutionHistory:
    """Create an execution history instance."""
    return ExecutionHistory(max_records_per_test, retention_days)
