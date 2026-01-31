"""
TestAI Agent - UI Change Detector

Detects and classifies changes in the UI that may
affect test stability and require test updates.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import re
import hashlib


class ChangeType(Enum):
    """Types of UI changes."""
    ELEMENT_ADDED = "element_added"
    ELEMENT_REMOVED = "element_removed"
    ELEMENT_MOVED = "element_moved"
    ATTRIBUTE_CHANGED = "attribute_changed"
    TEXT_CHANGED = "text_changed"
    STYLE_CHANGED = "style_changed"
    STRUCTURE_CHANGED = "structure_changed"
    SELECTOR_BROKEN = "selector_broken"
    NEW_INTERACTION = "new_interaction"
    REMOVED_INTERACTION = "removed_interaction"


class ChangeSeverity(Enum):
    """Severity of a UI change."""
    CRITICAL = "critical"  # Test will definitely fail
    HIGH = "high"  # Test likely to fail
    MEDIUM = "medium"  # Test may fail
    LOW = "low"  # Minor change, unlikely to affect tests
    INFO = "info"  # Informational only


@dataclass
class ElementState:
    """State of an element at a point in time."""
    element_id: str
    tag: str
    attributes: Dict[str, str]
    text_content: str
    xpath: str
    parent_xpath: str
    children_count: int
    is_visible: bool
    is_interactive: bool
    fingerprint: str  # Hash of key attributes


@dataclass
class UIChange:
    """A detected UI change."""
    change_id: str
    change_type: ChangeType
    severity: ChangeSeverity
    description: str
    element_xpath: str
    old_value: Optional[str]
    new_value: Optional[str]
    affected_selectors: List[str]
    suggested_action: str
    detected_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChangeReport:
    """Report of detected changes."""
    report_id: str
    baseline_snapshot: str
    current_snapshot: str
    total_changes: int
    critical_changes: int
    high_changes: int
    medium_changes: int
    low_changes: int
    changes: List[UIChange]
    affected_tests: List[str]
    generated_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class ChangeDetector:
    """
    Detects UI changes that affect test stability.

    Features:
    - Element fingerprinting
    - Change classification
    - Impact analysis
    - Selector breakage detection
    - Structural diff analysis
    """

    # Attributes that are critical for selector stability
    CRITICAL_ATTRIBUTES = {
        "id", "data-testid", "data-test", "data-cy",
        "name", "role", "aria-label", "type",
    }

    # Attributes that often change but don't break tests
    VOLATILE_ATTRIBUTES = {
        "class", "style", "href", "src", "data-*",
    }

    def __init__(self):
        """Initialize the detector."""
        self._snapshots: Dict[str, Dict[str, ElementState]] = {}
        self._change_counter = 0
        self._report_counter = 0
        self._change_history: List[UIChange] = []

        # Selector to test mappings
        self._selector_test_map: Dict[str, Set[str]] = {}

    def capture_snapshot(
        self,
        snapshot_name: str,
        elements: List[Dict[str, Any]],
    ) -> str:
        """Capture a UI snapshot for comparison."""
        element_states = {}

        for elem in elements:
            state = self._create_element_state(elem)
            element_states[state.xpath] = state

        self._snapshots[snapshot_name] = element_states
        return snapshot_name

    def _create_element_state(self, elem: Dict[str, Any]) -> ElementState:
        """Create an element state from raw element data."""
        attributes = elem.get("attributes", {})

        # Create fingerprint from stable attributes
        fingerprint_parts = [
            elem.get("tag", ""),
            attributes.get("id", ""),
            attributes.get("data-testid", ""),
            attributes.get("name", ""),
            attributes.get("role", ""),
        ]
        fingerprint = hashlib.md5(
            "|".join(fingerprint_parts).encode()
        ).hexdigest()[:12]

        return ElementState(
            element_id=elem.get("id", ""),
            tag=elem.get("tag", "div"),
            attributes=attributes,
            text_content=elem.get("text", "")[:100],
            xpath=elem.get("xpath", ""),
            parent_xpath=elem.get("parent_xpath", ""),
            children_count=elem.get("children_count", 0),
            is_visible=elem.get("visible", True),
            is_interactive=elem.get("interactive", False),
            fingerprint=fingerprint,
        )

    def register_selector_test(self, selector: str, test_id: str):
        """Register which test uses which selector."""
        if selector not in self._selector_test_map:
            self._selector_test_map[selector] = set()
        self._selector_test_map[selector].add(test_id)

    def compare_snapshots(
        self,
        baseline_name: str,
        current_name: str,
    ) -> ChangeReport:
        """Compare two snapshots and detect changes."""
        self._report_counter += 1
        report_id = f"CHANGE-{self._report_counter:05d}"

        baseline = self._snapshots.get(baseline_name, {})
        current = self._snapshots.get(current_name, {})

        changes = []

        # Find removed elements
        for xpath, old_state in baseline.items():
            if xpath not in current:
                changes.append(self._create_removal_change(old_state))

        # Find added elements
        for xpath, new_state in current.items():
            if xpath not in baseline:
                changes.append(self._create_addition_change(new_state))

        # Find modified elements
        for xpath, new_state in current.items():
            if xpath in baseline:
                old_state = baseline[xpath]
                element_changes = self._detect_element_changes(old_state, new_state)
                changes.extend(element_changes)

        # Collect affected tests
        affected_tests = self._find_affected_tests(changes)

        # Count by severity
        severity_counts = {s: 0 for s in ChangeSeverity}
        for change in changes:
            severity_counts[change.severity] += 1

        self._change_history.extend(changes)

        return ChangeReport(
            report_id=report_id,
            baseline_snapshot=baseline_name,
            current_snapshot=current_name,
            total_changes=len(changes),
            critical_changes=severity_counts[ChangeSeverity.CRITICAL],
            high_changes=severity_counts[ChangeSeverity.HIGH],
            medium_changes=severity_counts[ChangeSeverity.MEDIUM],
            low_changes=severity_counts[ChangeSeverity.LOW],
            changes=changes,
            affected_tests=list(affected_tests),
            generated_at=datetime.now(),
        )

    def _create_removal_change(self, old_state: ElementState) -> UIChange:
        """Create a change for a removed element."""
        self._change_counter += 1

        severity = ChangeSeverity.HIGH
        if old_state.is_interactive:
            severity = ChangeSeverity.CRITICAL

        affected = self._find_selectors_for_element(old_state)

        return UIChange(
            change_id=f"CHG-{self._change_counter:06d}",
            change_type=ChangeType.ELEMENT_REMOVED,
            severity=severity,
            description=f"Element {old_state.tag} removed from DOM",
            element_xpath=old_state.xpath,
            old_value=old_state.fingerprint,
            new_value=None,
            affected_selectors=affected,
            suggested_action="Find alternative element or update test",
            detected_at=datetime.now(),
            metadata={"tag": old_state.tag, "was_interactive": old_state.is_interactive},
        )

    def _create_addition_change(self, new_state: ElementState) -> UIChange:
        """Create a change for an added element."""
        self._change_counter += 1

        return UIChange(
            change_id=f"CHG-{self._change_counter:06d}",
            change_type=ChangeType.ELEMENT_ADDED,
            severity=ChangeSeverity.INFO,
            description=f"New {new_state.tag} element added",
            element_xpath=new_state.xpath,
            old_value=None,
            new_value=new_state.fingerprint,
            affected_selectors=[],
            suggested_action="Consider adding new tests for this element",
            detected_at=datetime.now(),
            metadata={
                "tag": new_state.tag,
                "is_interactive": new_state.is_interactive,
            },
        )

    def _detect_element_changes(
        self,
        old: ElementState,
        new: ElementState,
    ) -> List[UIChange]:
        """Detect changes between two states of the same element."""
        changes = []

        # Check critical attribute changes
        for attr in self.CRITICAL_ATTRIBUTES:
            old_val = old.attributes.get(attr)
            new_val = new.attributes.get(attr)

            if old_val != new_val:
                self._change_counter += 1

                severity = ChangeSeverity.CRITICAL if attr in {"id", "data-testid"} else ChangeSeverity.HIGH

                affected = self._find_selectors_for_attribute(attr, old_val)

                changes.append(UIChange(
                    change_id=f"CHG-{self._change_counter:06d}",
                    change_type=ChangeType.ATTRIBUTE_CHANGED,
                    severity=severity,
                    description=f"Critical attribute '{attr}' changed",
                    element_xpath=old.xpath,
                    old_value=old_val,
                    new_value=new_val,
                    affected_selectors=affected,
                    suggested_action=f"Update selectors using {attr}='{old_val}'",
                    detected_at=datetime.now(),
                    metadata={"attribute": attr},
                ))

        # Check text content changes
        if old.text_content != new.text_content:
            self._change_counter += 1

            severity = ChangeSeverity.MEDIUM if old.is_interactive else ChangeSeverity.LOW

            changes.append(UIChange(
                change_id=f"CHG-{self._change_counter:06d}",
                change_type=ChangeType.TEXT_CHANGED,
                severity=severity,
                description="Text content changed",
                element_xpath=old.xpath,
                old_value=old.text_content[:50],
                new_value=new.text_content[:50],
                affected_selectors=[],
                suggested_action="Update text-based selectors if used",
                detected_at=datetime.now(),
            ))

        # Check visibility changes
        if old.is_visible != new.is_visible:
            self._change_counter += 1

            changes.append(UIChange(
                change_id=f"CHG-{self._change_counter:06d}",
                change_type=ChangeType.STYLE_CHANGED,
                severity=ChangeSeverity.HIGH if not new.is_visible else ChangeSeverity.MEDIUM,
                description=f"Element visibility changed to {new.is_visible}",
                element_xpath=old.xpath,
                old_value=str(old.is_visible),
                new_value=str(new.is_visible),
                affected_selectors=self._find_selectors_for_element(old),
                suggested_action="Check if element interactions still work",
                detected_at=datetime.now(),
            ))

        return changes

    def _find_selectors_for_element(self, state: ElementState) -> List[str]:
        """Find selectors that might target this element."""
        potential_selectors = []

        if state.element_id:
            potential_selectors.append(f"#{state.element_id}")

        if "data-testid" in state.attributes:
            potential_selectors.append(f'[data-testid="{state.attributes["data-testid"]}"]')

        if "name" in state.attributes:
            potential_selectors.append(f'[name="{state.attributes["name"]}"]')

        return potential_selectors

    def _find_selectors_for_attribute(self, attr: str, value: Optional[str]) -> List[str]:
        """Find selectors using a specific attribute value."""
        if not value:
            return []

        selectors = []

        if attr == "id":
            selectors.append(f"#{value}")
        elif attr in {"data-testid", "data-test", "data-cy"}:
            selectors.append(f'[{attr}="{value}"]')
        elif attr == "name":
            selectors.append(f'[name="{value}"]')
        elif attr == "role":
            selectors.append(f'[role="{value}"]')

        return selectors

    def _find_affected_tests(self, changes: List[UIChange]) -> Set[str]:
        """Find tests affected by changes."""
        affected = set()

        for change in changes:
            for selector in change.affected_selectors:
                if selector in self._selector_test_map:
                    affected.update(self._selector_test_map[selector])

        return affected

    def detect_selector_breakage(
        self,
        selector: str,
        current_elements: List[Dict[str, Any]],
    ) -> Optional[UIChange]:
        """Detect if a selector no longer matches any elements."""
        # Simple selector matching simulation
        matched = False

        for elem in current_elements:
            if self._selector_matches(selector, elem):
                matched = True
                break

        if not matched:
            self._change_counter += 1

            return UIChange(
                change_id=f"CHG-{self._change_counter:06d}",
                change_type=ChangeType.SELECTOR_BROKEN,
                severity=ChangeSeverity.CRITICAL,
                description=f"Selector '{selector}' no longer matches any elements",
                element_xpath="",
                old_value=selector,
                new_value=None,
                affected_selectors=[selector],
                suggested_action="Use selector healer to find alternative",
                detected_at=datetime.now(),
            )

        return None

    def _selector_matches(self, selector: str, elem: Dict[str, Any]) -> bool:
        """Check if a selector matches an element (simplified)."""
        attributes = elem.get("attributes", {})

        # ID selector
        if selector.startswith("#"):
            return attributes.get("id") == selector[1:]

        # Attribute selector
        if selector.startswith("[") and "=" in selector:
            match = re.match(r'\[([^=]+)=["\']?([^"\'\]]+)', selector)
            if match:
                attr_name, attr_value = match.groups()
                return attributes.get(attr_name) == attr_value

        return False

    def get_change_history(
        self,
        change_type: Optional[ChangeType] = None,
        severity: Optional[ChangeSeverity] = None,
        limit: int = 100,
    ) -> List[UIChange]:
        """Get change history with optional filters."""
        changes = self._change_history

        if change_type:
            changes = [c for c in changes if c.change_type == change_type]

        if severity:
            changes = [c for c in changes if c.severity == severity]

        return changes[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics."""
        type_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}

        for change in self._change_history:
            change_type = change.change_type.value
            type_counts[change_type] = type_counts.get(change_type, 0) + 1

            sev = change.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "snapshots_stored": len(self._snapshots),
            "total_changes_detected": len(self._change_history),
            "registered_selectors": len(self._selector_test_map),
            "change_type_distribution": type_counts,
            "severity_distribution": severity_counts,
        }

    def format_report(self, report: ChangeReport) -> str:
        """Format a change report."""
        lines = [
            "=" * 70,
            "  UI CHANGE DETECTION REPORT",
            "=" * 70,
            "",
            f"  Report ID: {report.report_id}",
            f"  Baseline: {report.baseline_snapshot}",
            f"  Current: {report.current_snapshot}",
            "",
            "-" * 70,
            "  SUMMARY",
            "-" * 70,
            "",
            f"  Total Changes: {report.total_changes}",
            f"  🔴 Critical: {report.critical_changes}",
            f"  🟠 High: {report.high_changes}",
            f"  🟡 Medium: {report.medium_changes}",
            f"  🟢 Low: {report.low_changes}",
            "",
        ]

        if report.affected_tests:
            lines.extend([
                "-" * 70,
                f"  AFFECTED TESTS ({len(report.affected_tests)})",
                "-" * 70,
                "",
            ])
            for test_id in report.affected_tests[:10]:
                lines.append(f"  • {test_id}")
            if len(report.affected_tests) > 10:
                lines.append(f"  ... and {len(report.affected_tests) - 10} more")
            lines.append("")

        if report.changes:
            lines.extend([
                "-" * 70,
                "  CHANGES",
                "-" * 70,
                "",
            ])

            severity_icons = {
                ChangeSeverity.CRITICAL: "🔴",
                ChangeSeverity.HIGH: "🟠",
                ChangeSeverity.MEDIUM: "🟡",
                ChangeSeverity.LOW: "🟢",
                ChangeSeverity.INFO: "ℹ️",
            }

            for change in report.changes[:15]:
                icon = severity_icons.get(change.severity, "?")
                lines.append(f"  {icon} [{change.change_type.value}] {change.description}")
                if change.suggested_action:
                    lines.append(f"     → {change.suggested_action}")
                lines.append("")

            if len(report.changes) > 15:
                lines.append(f"  ... and {len(report.changes) - 15} more changes")

        lines.extend(["", "=" * 70])
        return "\n".join(lines)


def create_change_detector() -> ChangeDetector:
    """Create a change detector instance."""
    return ChangeDetector()
