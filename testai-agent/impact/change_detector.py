"""
TestAI Agent - Change Detector

Detects and categorizes code changes from git diffs
or file comparisons for impact analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import re


class ChangeType(Enum):
    """Types of code changes."""
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"
    MOVED = "moved"


@dataclass
class CodeChange:
    """A single code change."""
    file_path: str
    change_type: ChangeType
    old_path: Optional[str] = None  # For renames
    added_lines: int = 0
    deleted_lines: int = 0
    modified_functions: List[str] = field(default_factory=list)
    modified_classes: List[str] = field(default_factory=list)
    affected_imports: List[str] = field(default_factory=list)
    is_test_file: bool = False
    content_preview: str = ""


@dataclass
class ChangeSet:
    """A set of changes (e.g., from a commit)."""
    id: str
    description: str
    changes: List[CodeChange]
    timestamp: datetime
    author: str = ""
    total_additions: int = 0
    total_deletions: int = 0
    files_changed: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class ChangeDetector:
    """
    Detects and categorizes code changes.

    Supports:
    - Git diff parsing
    - Function/class modification detection
    - Import analysis
    - Test file identification
    """

    # Patterns for extracting code elements
    FUNCTION_PATTERNS = {
        "python": re.compile(r"^\+?\s*def\s+(\w+)\s*\(", re.MULTILINE),
        "javascript": re.compile(r"^\+?\s*(function\s+(\w+)|(\w+)\s*=\s*(async\s+)?function|\b(\w+)\s*\([^)]*\)\s*{)", re.MULTILINE),
        "typescript": re.compile(r"^\+?\s*(function\s+(\w+)|(\w+)\s*=\s*(async\s+)?function|\b(\w+)\s*\([^)]*\)\s*:)", re.MULTILINE),
    }

    CLASS_PATTERNS = {
        "python": re.compile(r"^\+?\s*class\s+(\w+)", re.MULTILINE),
        "javascript": re.compile(r"^\+?\s*class\s+(\w+)", re.MULTILINE),
        "typescript": re.compile(r"^\+?\s*class\s+(\w+)", re.MULTILINE),
    }

    IMPORT_PATTERNS = {
        "python": re.compile(r"^\+?\s*(from\s+[\w.]+\s+import|import\s+[\w.]+)", re.MULTILINE),
        "javascript": re.compile(r"^\+?\s*(import\s+.*from|require\s*\()", re.MULTILINE),
        "typescript": re.compile(r"^\+?\s*(import\s+.*from|require\s*\()", re.MULTILINE),
    }

    TEST_FILE_PATTERNS = [
        r"test_.*\.py$",
        r".*_test\.py$",
        r".*\.test\.(js|ts|jsx|tsx)$",
        r".*\.spec\.(js|ts|jsx|tsx)$",
        r"tests?/.*\.(py|js|ts)$",
        r"__tests__/.*\.(js|ts|jsx|tsx)$",
    ]

    def __init__(self):
        """Initialize the change detector."""
        self._test_patterns = [re.compile(p) for p in self.TEST_FILE_PATTERNS]

    def parse_git_diff(
        self,
        diff_content: str,
        change_id: str = "",
        description: str = "",
    ) -> ChangeSet:
        """Parse a git diff into a ChangeSet."""
        changes = []
        current_file = None
        current_change_type = None
        old_path = None
        added_lines = 0
        deleted_lines = 0
        diff_content_buffer = []

        for line in diff_content.split("\n"):
            # New file marker
            if line.startswith("diff --git"):
                # Save previous file if exists
                if current_file:
                    changes.append(self._create_change(
                        current_file,
                        current_change_type,
                        old_path,
                        added_lines,
                        deleted_lines,
                        "\n".join(diff_content_buffer),
                    ))

                # Reset for new file
                parts = line.split()
                if len(parts) >= 4:
                    current_file = parts[3][2:]  # Remove b/ prefix
                    old_path = parts[2][2:]  # Remove a/ prefix
                current_change_type = ChangeType.MODIFIED
                added_lines = 0
                deleted_lines = 0
                diff_content_buffer = []

            # New file indicator
            elif line.startswith("new file"):
                current_change_type = ChangeType.ADDED

            # Deleted file indicator
            elif line.startswith("deleted file"):
                current_change_type = ChangeType.DELETED

            # Renamed file indicator
            elif line.startswith("rename from"):
                current_change_type = ChangeType.RENAMED
                old_path = line.replace("rename from ", "")

            elif line.startswith("rename to") and current_change_type == ChangeType.RENAMED:
                current_file = line.replace("rename to ", "")

            # Count additions and deletions
            elif line.startswith("+") and not line.startswith("+++"):
                added_lines += 1
                diff_content_buffer.append(line)

            elif line.startswith("-") and not line.startswith("---"):
                deleted_lines += 1
                diff_content_buffer.append(line)

        # Save last file
        if current_file:
            changes.append(self._create_change(
                current_file,
                current_change_type,
                old_path,
                added_lines,
                deleted_lines,
                "\n".join(diff_content_buffer),
            ))

        total_additions = sum(c.added_lines for c in changes)
        total_deletions = sum(c.deleted_lines for c in changes)

        return ChangeSet(
            id=change_id or f"CS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            description=description,
            changes=changes,
            timestamp=datetime.now(),
            total_additions=total_additions,
            total_deletions=total_deletions,
            files_changed=len(changes),
        )

    def parse_file_list(
        self,
        files: List[Dict[str, Any]],
        change_id: str = "",
        description: str = "",
    ) -> ChangeSet:
        """Create a ChangeSet from a list of file changes."""
        changes = []

        for file_info in files:
            change = CodeChange(
                file_path=file_info.get("path", ""),
                change_type=ChangeType(file_info.get("type", "modified")),
                old_path=file_info.get("old_path"),
                added_lines=file_info.get("added", 0),
                deleted_lines=file_info.get("deleted", 0),
                modified_functions=file_info.get("functions", []),
                modified_classes=file_info.get("classes", []),
                is_test_file=self._is_test_file(file_info.get("path", "")),
            )
            changes.append(change)

        return ChangeSet(
            id=change_id or f"CS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            description=description,
            changes=changes,
            timestamp=datetime.now(),
            total_additions=sum(c.added_lines for c in changes),
            total_deletions=sum(c.deleted_lines for c in changes),
            files_changed=len(changes),
        )

    def extract_modified_elements(
        self,
        diff_content: str,
        language: str = "python",
    ) -> Dict[str, List[str]]:
        """Extract modified functions and classes from diff."""
        results = {
            "functions": [],
            "classes": [],
            "imports": [],
        }

        func_pattern = self.FUNCTION_PATTERNS.get(language)
        class_pattern = self.CLASS_PATTERNS.get(language)
        import_pattern = self.IMPORT_PATTERNS.get(language)

        if func_pattern:
            matches = func_pattern.findall(diff_content)
            # Handle different match group structures
            for match in matches:
                if isinstance(match, tuple):
                    # Get first non-empty group
                    name = next((m for m in match if m), None)
                else:
                    name = match
                if name and name not in results["functions"]:
                    results["functions"].append(name)

        if class_pattern:
            matches = class_pattern.findall(diff_content)
            for match in matches:
                if match and match not in results["classes"]:
                    results["classes"].append(match)

        if import_pattern:
            matches = import_pattern.findall(diff_content)
            for match in matches:
                if match and match not in results["imports"]:
                    results["imports"].append(match)

        return results

    def categorize_changes(
        self,
        changeset: ChangeSet,
    ) -> Dict[str, List[CodeChange]]:
        """Categorize changes by type."""
        categories = {
            "source_code": [],
            "test_code": [],
            "configuration": [],
            "documentation": [],
            "other": [],
        }

        config_extensions = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}
        doc_extensions = {".md", ".rst", ".txt", ".adoc"}

        for change in changeset.changes:
            path = change.file_path.lower()

            if change.is_test_file:
                categories["test_code"].append(change)
            elif any(path.endswith(ext) for ext in config_extensions):
                categories["configuration"].append(change)
            elif any(path.endswith(ext) for ext in doc_extensions):
                categories["documentation"].append(change)
            elif path.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go")):
                categories["source_code"].append(change)
            else:
                categories["other"].append(change)

        return categories

    def get_affected_modules(
        self,
        changeset: ChangeSet,
    ) -> Set[str]:
        """Get the set of affected modules/packages."""
        modules = set()

        for change in changeset.changes:
            parts = change.file_path.split("/")
            # Get top-level directory as module
            if len(parts) > 1:
                modules.add(parts[0])
            # Also add parent directories for deeper files
            for i in range(len(parts) - 1):
                modules.add("/".join(parts[:i + 1]))

        return modules

    def calculate_change_risk(
        self,
        change: CodeChange,
    ) -> float:
        """Calculate risk score for a change (0-1)."""
        risk = 0.0

        # More lines changed = higher risk
        total_lines = change.added_lines + change.deleted_lines
        if total_lines > 100:
            risk += 0.3
        elif total_lines > 50:
            risk += 0.2
        elif total_lines > 10:
            risk += 0.1

        # Function/class modifications = higher risk
        if change.modified_functions:
            risk += 0.2 * min(len(change.modified_functions) / 5, 1.0)
        if change.modified_classes:
            risk += 0.2 * min(len(change.modified_classes) / 3, 1.0)

        # Deletions are riskier than additions
        if change.deleted_lines > change.added_lines:
            risk += 0.1

        # Test file changes have lower risk (for production)
        if change.is_test_file:
            risk *= 0.5

        return min(risk, 1.0)

    def _create_change(
        self,
        file_path: str,
        change_type: Optional[ChangeType],
        old_path: Optional[str],
        added_lines: int,
        deleted_lines: int,
        diff_content: str,
    ) -> CodeChange:
        """Create a CodeChange from parsed data."""
        language = self._detect_language(file_path)
        elements = self.extract_modified_elements(diff_content, language)

        return CodeChange(
            file_path=file_path,
            change_type=change_type or ChangeType.MODIFIED,
            old_path=old_path if old_path != file_path else None,
            added_lines=added_lines,
            deleted_lines=deleted_lines,
            modified_functions=elements["functions"],
            modified_classes=elements["classes"],
            affected_imports=elements["imports"],
            is_test_file=self._is_test_file(file_path),
            content_preview=diff_content[:500] if diff_content else "",
        )

    def _is_test_file(self, file_path: str) -> bool:
        """Check if a file is a test file."""
        return any(pattern.search(file_path) for pattern in self._test_patterns)

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
        }

        for ext, lang in extension_map.items():
            if file_path.endswith(ext):
                return lang

        return "python"  # Default

    def format_changeset(self, changeset: ChangeSet) -> str:
        """Format a ChangeSet as readable text."""
        lines = [
            "=" * 60,
            f"  CHANGESET: {changeset.id}",
            "=" * 60,
            "",
            f"  Description: {changeset.description}",
            f"  Timestamp: {changeset.timestamp.strftime('%Y-%m-%d %H:%M')}",
            f"  Author: {changeset.author or 'Unknown'}",
            "",
            f"  Files Changed: {changeset.files_changed}",
            f"  Lines Added: +{changeset.total_additions}",
            f"  Lines Deleted: -{changeset.total_deletions}",
            "",
            "-" * 60,
            "  CHANGES",
            "-" * 60,
        ]

        type_icons = {
            ChangeType.ADDED: "➕",
            ChangeType.MODIFIED: "📝",
            ChangeType.DELETED: "➖",
            ChangeType.RENAMED: "📛",
            ChangeType.MOVED: "📦",
        }

        for change in changeset.changes:
            icon = type_icons.get(change.change_type, "•")
            risk = self.calculate_change_risk(change)
            risk_indicator = "🔴" if risk > 0.6 else "🟡" if risk > 0.3 else "🟢"

            lines.append(f"\n  {icon} {change.file_path} {risk_indicator}")
            lines.append(f"     +{change.added_lines} -{change.deleted_lines}")

            if change.modified_functions:
                funcs = ", ".join(change.modified_functions[:5])
                if len(change.modified_functions) > 5:
                    funcs += f" (+{len(change.modified_functions) - 5} more)"
                lines.append(f"     Functions: {funcs}")

            if change.modified_classes:
                classes = ", ".join(change.modified_classes[:3])
                lines.append(f"     Classes: {classes}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_change_detector() -> ChangeDetector:
    """Create a change detector instance."""
    return ChangeDetector()
