"""
TestAI Agent - Code Correlator

Correlates test failures with code changes to identify
which changes may have caused failures.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
import re


class ChangeType(Enum):
    """Types of code changes."""
    ADDITION = "addition"
    MODIFICATION = "modification"
    DELETION = "deletion"
    RENAME = "rename"
    MOVE = "move"


class CorrelationStrength(Enum):
    """Strength of correlation between change and failure."""
    DEFINITE = "definite"  # Very high correlation
    STRONG = "strong"  # High correlation
    MODERATE = "moderate"  # Moderate correlation
    WEAK = "weak"  # Low correlation
    NONE = "none"  # No correlation


@dataclass
class CodeChange:
    """A code change record."""
    change_id: str
    file_path: str
    change_type: ChangeType
    author: str
    timestamp: datetime
    description: str
    lines_added: int = 0
    lines_removed: int = 0
    affected_functions: List[str] = field(default_factory=list)
    commit_hash: Optional[str] = None


@dataclass
class ChangeCorrelation:
    """Correlation between a change and a failure."""
    correlation_id: str
    test_id: str
    change: CodeChange
    strength: CorrelationStrength
    confidence: float
    reasons: List[str]
    file_overlap: float  # 0.0 to 1.0
    time_proximity_hours: float


@dataclass
class CorrelationReport:
    """Complete correlation analysis report."""
    test_id: str
    error_message: str
    total_changes_analyzed: int
    correlations: List[ChangeCorrelation]
    most_likely_cause: Optional[ChangeCorrelation]
    summary: str


class CodeCorrelator:
    """
    Correlates test failures with code changes.

    Features:
    - Change-to-failure correlation
    - File path matching
    - Time-based correlation
    - Author tracking
    - Impact scoring
    """

    def __init__(self):
        """Initialize the code correlator."""
        self._changes: List[CodeChange] = []
        self._test_files: Dict[str, Set[str]] = {}  # test_id -> related files
        self._correlation_counter = 0
        self._change_counter = 0

    def register_change(
        self,
        file_path: str,
        change_type: ChangeType,
        author: str,
        description: str,
        lines_added: int = 0,
        lines_removed: int = 0,
        affected_functions: Optional[List[str]] = None,
        commit_hash: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> CodeChange:
        """Register a code change."""
        self._change_counter += 1
        change = CodeChange(
            change_id=f"CHG-{self._change_counter:05d}",
            file_path=file_path,
            change_type=change_type,
            author=author,
            timestamp=timestamp or datetime.now(),
            description=description,
            lines_added=lines_added,
            lines_removed=lines_removed,
            affected_functions=affected_functions or [],
            commit_hash=commit_hash,
        )
        self._changes.append(change)
        return change

    def register_test_files(
        self,
        test_id: str,
        related_files: List[str],
    ):
        """Register files related to a test."""
        self._test_files[test_id] = set(related_files)

    def correlate(
        self,
        test_id: str,
        error_message: str,
        stack_trace: Optional[str] = None,
        failure_time: Optional[datetime] = None,
        lookback_hours: int = 24,
    ) -> CorrelationReport:
        """Correlate a test failure with recent changes."""
        failure_time = failure_time or datetime.now()
        cutoff_time = failure_time - timedelta(hours=lookback_hours)

        # Get recent changes
        recent_changes = [
            c for c in self._changes
            if c.timestamp >= cutoff_time
        ]

        # Extract files from stack trace
        stack_files = self._extract_files_from_stack(stack_trace) if stack_trace else set()

        # Get test-related files
        test_files = self._test_files.get(test_id, set())
        all_relevant_files = stack_files | test_files

        # Correlate each change
        correlations = []
        for change in recent_changes:
            correlation = self._correlate_change(
                test_id=test_id,
                change=change,
                relevant_files=all_relevant_files,
                failure_time=failure_time,
                error_message=error_message,
            )
            if correlation.strength != CorrelationStrength.NONE:
                correlations.append(correlation)

        # Sort by confidence
        correlations.sort(key=lambda c: -c.confidence)

        # Identify most likely cause
        most_likely = correlations[0] if correlations else None

        # Generate summary
        summary = self._generate_summary(correlations, most_likely)

        return CorrelationReport(
            test_id=test_id,
            error_message=error_message,
            total_changes_analyzed=len(recent_changes),
            correlations=correlations,
            most_likely_cause=most_likely,
            summary=summary,
        )

    def _correlate_change(
        self,
        test_id: str,
        change: CodeChange,
        relevant_files: Set[str],
        failure_time: datetime,
        error_message: str,
    ) -> ChangeCorrelation:
        """Correlate a single change with the failure."""
        self._correlation_counter += 1

        reasons = []
        confidence_factors = []

        # Check file overlap
        file_overlap = self._calculate_file_overlap(change.file_path, relevant_files)
        if file_overlap > 0:
            reasons.append(f"File overlap: {change.file_path}")
            confidence_factors.append(file_overlap)

        # Check time proximity
        time_diff = (failure_time - change.timestamp).total_seconds() / 3600
        time_proximity = max(0, 1 - (time_diff / 24))  # Decay over 24 hours
        if time_proximity > 0.5:
            reasons.append(f"Recent change ({time_diff:.1f}h ago)")
            confidence_factors.append(time_proximity * 0.5)

        # Check change impact
        change_impact = self._calculate_change_impact(change)
        if change_impact > 0.3:
            reasons.append(f"Significant change impact ({change.lines_added + change.lines_removed} lines)")
            confidence_factors.append(change_impact * 0.3)

        # Check error message correlation
        error_correlation = self._check_error_correlation(change, error_message)
        if error_correlation > 0:
            reasons.append("Error mentions related code")
            confidence_factors.append(error_correlation * 0.4)

        # Calculate overall confidence
        confidence = min(0.95, sum(confidence_factors))

        # Determine strength
        strength = self._determine_strength(confidence, file_overlap, time_proximity)

        return ChangeCorrelation(
            correlation_id=f"COR-{self._correlation_counter:05d}",
            test_id=test_id,
            change=change,
            strength=strength,
            confidence=confidence,
            reasons=reasons,
            file_overlap=file_overlap,
            time_proximity_hours=time_diff,
        )

    def _calculate_file_overlap(
        self,
        change_file: str,
        relevant_files: Set[str],
    ) -> float:
        """Calculate how much the changed file overlaps with relevant files."""
        if not relevant_files:
            return 0.0

        # Normalize paths
        change_path = change_file.replace("\\", "/").lower()

        for rel_file in relevant_files:
            rel_path = rel_file.replace("\\", "/").lower()

            # Exact match
            if change_path == rel_path:
                return 1.0

            # Partial match (same directory or file name)
            if change_path.split("/")[-1] == rel_path.split("/")[-1]:
                return 0.8

            # Module/directory match
            change_dir = "/".join(change_path.split("/")[:-1])
            rel_dir = "/".join(rel_path.split("/")[:-1])
            if change_dir and rel_dir and change_dir == rel_dir:
                return 0.6

        return 0.0

    def _calculate_change_impact(self, change: CodeChange) -> float:
        """Calculate impact score of a change."""
        total_lines = change.lines_added + change.lines_removed

        if total_lines == 0:
            return 0.1

        # Scale based on change size
        if total_lines > 100:
            return 0.9
        elif total_lines > 50:
            return 0.7
        elif total_lines > 20:
            return 0.5
        elif total_lines > 5:
            return 0.3

        return 0.2

    def _check_error_correlation(
        self,
        change: CodeChange,
        error_message: str,
    ) -> float:
        """Check if error message correlates with the change."""
        error_lower = error_message.lower()

        # Check file name
        file_name = change.file_path.split("/")[-1].replace("_", " ").replace(".", " ").lower()
        for word in file_name.split():
            if len(word) > 3 and word in error_lower:
                return 0.6

        # Check function names
        for func in change.affected_functions:
            if func.lower() in error_lower:
                return 0.8

        # Check description keywords
        desc_words = change.description.lower().split()
        for word in desc_words:
            if len(word) > 4 and word in error_lower:
                return 0.4

        return 0.0

    def _determine_strength(
        self,
        confidence: float,
        file_overlap: float,
        time_proximity: float,
    ) -> CorrelationStrength:
        """Determine correlation strength."""
        if confidence >= 0.8 and file_overlap >= 0.8:
            return CorrelationStrength.DEFINITE
        elif confidence >= 0.6 or (file_overlap >= 0.6 and time_proximity >= 0.5):
            return CorrelationStrength.STRONG
        elif confidence >= 0.4:
            return CorrelationStrength.MODERATE
        elif confidence >= 0.2:
            return CorrelationStrength.WEAK
        return CorrelationStrength.NONE

    def _extract_files_from_stack(self, stack_trace: str) -> Set[str]:
        """Extract file paths from stack trace."""
        files = set()

        patterns = [
            r"at\s+.*\((.*?):(\d+)\)",
            r"File \"(.*?)\"",
            r"([\w./\\]+\.\w+):(\d+)",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, stack_trace)
            for match in matches:
                if isinstance(match, tuple):
                    files.add(match[0])
                else:
                    files.add(match)

        return files

    def _generate_summary(
        self,
        correlations: List[ChangeCorrelation],
        most_likely: Optional[ChangeCorrelation],
    ) -> str:
        """Generate a summary of the correlation analysis."""
        if not correlations:
            return "No correlations found with recent changes."

        strong_correlations = [
            c for c in correlations
            if c.strength in {CorrelationStrength.DEFINITE, CorrelationStrength.STRONG}
        ]

        if not strong_correlations:
            return f"Found {len(correlations)} weak correlations. Manual investigation recommended."

        if most_likely:
            return (
                f"Found {len(strong_correlations)} strong correlation(s). "
                f"Most likely cause: {most_likely.change.file_path} by {most_likely.change.author} "
                f"({most_likely.time_proximity_hours:.1f}h ago) - {most_likely.confidence:.0%} confidence."
            )

        return f"Found {len(strong_correlations)} strong correlations requiring investigation."

    def get_change_history(
        self,
        file_path: Optional[str] = None,
        author: Optional[str] = None,
        hours: int = 24,
    ) -> List[CodeChange]:
        """Get change history with optional filters."""
        cutoff = datetime.now() - timedelta(hours=hours)

        filtered = self._changes

        if file_path:
            filtered = [c for c in filtered if file_path in c.file_path]

        if author:
            filtered = [c for c in filtered if c.author == author]

        filtered = [c for c in filtered if c.timestamp >= cutoff]

        return sorted(filtered, key=lambda c: c.timestamp, reverse=True)

    def get_author_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics by author."""
        stats: Dict[str, Dict[str, Any]] = {}

        for change in self._changes:
            if change.author not in stats:
                stats[change.author] = {
                    "total_changes": 0,
                    "lines_added": 0,
                    "lines_removed": 0,
                    "files_touched": set(),
                }

            stats[change.author]["total_changes"] += 1
            stats[change.author]["lines_added"] += change.lines_added
            stats[change.author]["lines_removed"] += change.lines_removed
            stats[change.author]["files_touched"].add(change.file_path)

        # Convert sets to counts
        for author in stats:
            stats[author]["files_touched"] = len(stats[author]["files_touched"])

        return stats

    def format_report(self, report: CorrelationReport) -> str:
        """Format correlation report as readable text."""
        lines = [
            "=" * 60,
            "  CODE CORRELATION REPORT",
            "=" * 60,
            "",
            f"  Test: {report.test_id}",
            f"  Changes Analyzed: {report.total_changes_analyzed}",
            f"  Correlations Found: {len(report.correlations)}",
            "",
            "-" * 60,
            "  SUMMARY",
            "-" * 60,
            f"  {report.summary}",
            "",
        ]

        if report.most_likely_cause:
            cause = report.most_likely_cause
            lines.extend([
                "-" * 60,
                "  MOST LIKELY CAUSE",
                "-" * 60,
                f"  File: {cause.change.file_path}",
                f"  Author: {cause.change.author}",
                f"  Time: {cause.time_proximity_hours:.1f} hours ago",
                f"  Confidence: {cause.confidence:.0%}",
                f"  Strength: {cause.strength.value}",
                "",
                "  Reasons:",
            ])
            for reason in cause.reasons:
                lines.append(f"    - {reason}")

        if report.correlations and len(report.correlations) > 1:
            lines.extend([
                "",
                "-" * 60,
                "  OTHER CORRELATIONS",
                "-" * 60,
            ])
            for corr in report.correlations[1:5]:  # Skip first (already shown)
                lines.append(
                    f"  - {corr.change.file_path} ({corr.strength.value}, {corr.confidence:.0%})"
                )

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_code_correlator() -> CodeCorrelator:
    """Create a code correlator instance."""
    return CodeCorrelator()
