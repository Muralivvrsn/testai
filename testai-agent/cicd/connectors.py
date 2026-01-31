"""
TestAI Agent - CI/CD Connectors

Connectors for integrating with various CI/CD
platforms like GitHub Actions, GitLab CI, and Jenkins.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import json
import os


class ConnectorType(Enum):
    """Supported CI/CD platforms."""
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    CIRCLECI = "circleci"
    AZURE_DEVOPS = "azure_devops"
    BITBUCKET = "bitbucket"
    TRAVIS_CI = "travis_ci"
    CUSTOM = "custom"


class PipelineStatus(Enum):
    """Status of a CI/CD pipeline."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILURE = "failure"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


@dataclass
class PipelineRun:
    """Information about a pipeline run."""
    run_id: str
    pipeline_name: str
    status: PipelineStatus
    branch: str
    commit_sha: str
    started_at: datetime
    completed_at: Optional[datetime]
    duration_sec: Optional[float]
    url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestJobResult:
    """Result of a test job in the pipeline."""
    job_id: str
    job_name: str
    status: PipelineStatus
    tests_run: int
    tests_passed: int
    tests_failed: int
    tests_skipped: int
    duration_sec: float
    artifacts: List[str] = field(default_factory=list)
    logs_url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineResult:
    """Complete result of a pipeline run."""
    result_id: str
    run: PipelineRun
    jobs: List[TestJobResult]
    overall_status: PipelineStatus
    total_tests: int
    total_passed: int
    total_failed: int
    coverage_pct: Optional[float]
    summary: str


class CICDConnector:
    """
    Base CI/CD connector.

    Features:
    - Multi-platform support
    - Pipeline status tracking
    - Test result aggregation
    - Environment detection
    """

    def __init__(
        self,
        connector_type: ConnectorType,
        config: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the connector."""
        self._type = connector_type
        self._config = config or {}
        self._runs: List[PipelineRun] = []
        self._results: List[PipelineResult] = []
        self._run_counter = 0
        self._result_counter = 0

        # Try to detect environment
        self._env = self._detect_environment()

    def _detect_environment(self) -> Dict[str, Any]:
        """Detect CI/CD environment from env vars."""
        env = {}

        # GitHub Actions
        if os.environ.get("GITHUB_ACTIONS"):
            env["platform"] = "github_actions"
            env["repository"] = os.environ.get("GITHUB_REPOSITORY", "")
            env["branch"] = os.environ.get("GITHUB_REF_NAME", "")
            env["commit_sha"] = os.environ.get("GITHUB_SHA", "")
            env["run_id"] = os.environ.get("GITHUB_RUN_ID", "")
            env["run_number"] = os.environ.get("GITHUB_RUN_NUMBER", "")

        # GitLab CI
        elif os.environ.get("GITLAB_CI"):
            env["platform"] = "gitlab_ci"
            env["repository"] = os.environ.get("CI_PROJECT_PATH", "")
            env["branch"] = os.environ.get("CI_COMMIT_BRANCH", "")
            env["commit_sha"] = os.environ.get("CI_COMMIT_SHA", "")
            env["pipeline_id"] = os.environ.get("CI_PIPELINE_ID", "")
            env["job_id"] = os.environ.get("CI_JOB_ID", "")

        # Jenkins
        elif os.environ.get("JENKINS_URL"):
            env["platform"] = "jenkins"
            env["job_name"] = os.environ.get("JOB_NAME", "")
            env["branch"] = os.environ.get("GIT_BRANCH", "")
            env["commit_sha"] = os.environ.get("GIT_COMMIT", "")
            env["build_number"] = os.environ.get("BUILD_NUMBER", "")

        # CircleCI
        elif os.environ.get("CIRCLECI"):
            env["platform"] = "circleci"
            env["repository"] = os.environ.get("CIRCLE_PROJECT_REPONAME", "")
            env["branch"] = os.environ.get("CIRCLE_BRANCH", "")
            env["commit_sha"] = os.environ.get("CIRCLE_SHA1", "")
            env["build_num"] = os.environ.get("CIRCLE_BUILD_NUM", "")

        # Azure DevOps
        elif os.environ.get("TF_BUILD"):
            env["platform"] = "azure_devops"
            env["repository"] = os.environ.get("BUILD_REPOSITORY_NAME", "")
            env["branch"] = os.environ.get("BUILD_SOURCEBRANCHNAME", "")
            env["commit_sha"] = os.environ.get("BUILD_SOURCEVERSION", "")
            env["build_id"] = os.environ.get("BUILD_BUILDID", "")

        else:
            env["platform"] = "local"
            env["branch"] = "unknown"
            env["commit_sha"] = "unknown"

        return env

    def get_environment(self) -> Dict[str, Any]:
        """Get detected CI/CD environment."""
        return self._env

    def is_ci_environment(self) -> bool:
        """Check if running in a CI environment."""
        return self._env.get("platform", "local") != "local"

    def create_pipeline_run(
        self,
        pipeline_name: str,
        branch: Optional[str] = None,
        commit_sha: Optional[str] = None,
    ) -> PipelineRun:
        """Create a new pipeline run record."""
        self._run_counter += 1
        run_id = f"RUN-{self._run_counter:05d}"

        run = PipelineRun(
            run_id=run_id,
            pipeline_name=pipeline_name,
            status=PipelineStatus.RUNNING,
            branch=branch or self._env.get("branch", "unknown"),
            commit_sha=commit_sha or self._env.get("commit_sha", "unknown"),
            started_at=datetime.now(),
            completed_at=None,
            duration_sec=None,
        )

        self._runs.append(run)
        return run

    def update_pipeline_status(
        self,
        run_id: str,
        status: PipelineStatus,
    ) -> Optional[PipelineRun]:
        """Update status of a pipeline run."""
        for run in self._runs:
            if run.run_id == run_id:
                run.status = status
                if status in (PipelineStatus.SUCCESS, PipelineStatus.FAILURE,
                              PipelineStatus.CANCELLED):
                    run.completed_at = datetime.now()
                    run.duration_sec = (
                        run.completed_at - run.started_at
                    ).total_seconds()
                return run
        return None

    def record_test_job(
        self,
        run_id: str,
        job_name: str,
        tests_run: int,
        tests_passed: int,
        tests_failed: int,
        tests_skipped: int = 0,
        duration_sec: float = 0.0,
        artifacts: Optional[List[str]] = None,
    ) -> TestJobResult:
        """Record results from a test job."""
        status = PipelineStatus.SUCCESS if tests_failed == 0 else PipelineStatus.FAILURE

        result = TestJobResult(
            job_id=f"{run_id}-job-{len(self._results) + 1}",
            job_name=job_name,
            status=status,
            tests_run=tests_run,
            tests_passed=tests_passed,
            tests_failed=tests_failed,
            tests_skipped=tests_skipped,
            duration_sec=duration_sec,
            artifacts=artifacts or [],
        )

        return result

    def complete_pipeline(
        self,
        run_id: str,
        jobs: List[TestJobResult],
        coverage_pct: Optional[float] = None,
    ) -> PipelineResult:
        """Complete a pipeline run with results."""
        self._result_counter += 1
        result_id = f"RESULT-{self._result_counter:05d}"

        # Find the run
        run = next((r for r in self._runs if r.run_id == run_id), None)
        if not run:
            raise ValueError(f"Run not found: {run_id}")

        # Aggregate results
        total_tests = sum(j.tests_run for j in jobs)
        total_passed = sum(j.tests_passed for j in jobs)
        total_failed = sum(j.tests_failed for j in jobs)

        # Determine overall status
        if any(j.status == PipelineStatus.FAILURE for j in jobs):
            overall_status = PipelineStatus.FAILURE
        else:
            overall_status = PipelineStatus.SUCCESS

        # Update run status
        self.update_pipeline_status(run_id, overall_status)

        # Generate summary
        summary = self._generate_summary(
            total_tests, total_passed, total_failed, coverage_pct
        )

        result = PipelineResult(
            result_id=result_id,
            run=run,
            jobs=jobs,
            overall_status=overall_status,
            total_tests=total_tests,
            total_passed=total_passed,
            total_failed=total_failed,
            coverage_pct=coverage_pct,
            summary=summary,
        )

        self._results.append(result)
        return result

    def _generate_summary(
        self,
        total: int,
        passed: int,
        failed: int,
        coverage: Optional[float],
    ) -> str:
        """Generate a pipeline summary."""
        lines = [
            f"Tests: {total} total, {passed} passed, {failed} failed",
        ]

        if coverage is not None:
            lines.append(f"Coverage: {coverage:.1f}%")

        if failed == 0:
            lines.append("Status: ✅ All tests passed")
        else:
            lines.append(f"Status: ❌ {failed} test(s) failed")

        return " | ".join(lines)

    def generate_status_check(
        self,
        result: PipelineResult,
    ) -> Dict[str, Any]:
        """Generate status check payload for GitHub/GitLab."""
        state = "success" if result.overall_status == PipelineStatus.SUCCESS else "failure"

        return {
            "state": state,
            "description": result.summary,
            "context": f"TestAI / {result.run.pipeline_name}",
            "target_url": result.run.url,
        }

    def generate_github_annotation(
        self,
        file_path: str,
        line: int,
        message: str,
        level: str = "error",
    ) -> str:
        """Generate GitHub Actions annotation."""
        return f"::{level} file={file_path},line={line}::{message}"

    def generate_gitlab_report(
        self,
        result: PipelineResult,
    ) -> Dict[str, Any]:
        """Generate GitLab JUnit report format."""
        testsuites = []

        for job in result.jobs:
            testsuite = {
                "name": job.job_name,
                "tests": job.tests_run,
                "failures": job.tests_failed,
                "skipped": job.tests_skipped,
                "time": job.duration_sec,
            }
            testsuites.append(testsuite)

        return {
            "testsuites": testsuites,
            "tests": result.total_tests,
            "failures": result.total_failed,
        }

    def get_pipeline_badge(
        self,
        status: PipelineStatus,
    ) -> Dict[str, str]:
        """Get badge data for pipeline status."""
        colors = {
            PipelineStatus.SUCCESS: "brightgreen",
            PipelineStatus.FAILURE: "red",
            PipelineStatus.RUNNING: "yellow",
            PipelineStatus.PENDING: "lightgrey",
            PipelineStatus.CANCELLED: "grey",
        }

        return {
            "label": "tests",
            "message": status.value,
            "color": colors.get(status, "lightgrey"),
        }

    def get_history(self, limit: int = 10) -> List[PipelineResult]:
        """Get recent pipeline results."""
        return self._results[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get connector statistics."""
        status_counts = {s.value: 0 for s in PipelineStatus}
        for result in self._results:
            status_counts[result.overall_status.value] += 1

        return {
            "connector_type": self._type.value,
            "is_ci": self.is_ci_environment(),
            "platform": self._env.get("platform", "local"),
            "total_runs": len(self._runs),
            "total_results": len(self._results),
            "results_by_status": status_counts,
        }

    def format_result(self, result: PipelineResult) -> str:
        """Format a pipeline result for display."""
        status_icons = {
            PipelineStatus.SUCCESS: "✅",
            PipelineStatus.FAILURE: "❌",
            PipelineStatus.RUNNING: "🔄",
            PipelineStatus.PENDING: "⏳",
            PipelineStatus.CANCELLED: "🚫",
        }

        icon = status_icons.get(result.overall_status, "❓")

        lines = [
            "=" * 55,
            f"  PIPELINE RESULT: {icon} {result.overall_status.value.upper()}",
            "=" * 55,
            "",
            f"  Pipeline: {result.run.pipeline_name}",
            f"  Branch: {result.run.branch}",
            f"  Commit: {result.run.commit_sha[:8] if result.run.commit_sha else 'N/A'}",
            "",
            "-" * 55,
            "  TEST RESULTS",
            "-" * 55,
            "",
            f"  Total Tests: {result.total_tests}",
            f"  Passed: {result.total_passed}",
            f"  Failed: {result.total_failed}",
        ]

        if result.coverage_pct is not None:
            lines.append(f"  Coverage: {result.coverage_pct:.1f}%")

        lines.append("")

        if result.jobs:
            lines.append("-" * 55)
            lines.append("  JOBS")
            lines.append("-" * 55)
            lines.append("")
            for job in result.jobs:
                job_icon = status_icons.get(job.status, "❓")
                lines.append(f"  {job_icon} {job.job_name}: {job.tests_passed}/{job.tests_run}")
            lines.append("")

        lines.append("=" * 55)
        return "\n".join(lines)


def create_connector(
    connector_type: ConnectorType = ConnectorType.GITHUB_ACTIONS,
    config: Optional[Dict[str, Any]] = None,
) -> CICDConnector:
    """Create a CI/CD connector instance."""
    return CICDConnector(
        connector_type=connector_type,
        config=config,
    )
