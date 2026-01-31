"""
TestAI Agent - Celebration System

Good QA engineers celebrate wins.
Finding bugs is exciting! Completing coverage is satisfying!

Design Philosophy:
- Celebrate meaningful accomplishments
- Don't over-celebrate small things
- Be genuine, not cheesy
- European restraint - warm but not excessive
"""

from dataclasses import dataclass
from typing import List, Optional
from enum import Enum
import random


class AchievementType(Enum):
    """Types of achievements to celebrate."""
    BUG_FOUND = "bug_found"
    CRITICAL_BUG = "critical_bug"
    EDGE_CASE = "edge_case"
    COVERAGE_COMPLETE = "coverage_complete"
    SECURITY_ISSUE = "security_issue"
    ACCESSIBILITY_ISSUE = "accessibility_issue"
    PERFORMANCE_ISSUE = "performance_issue"
    TEST_PASSED = "test_passed"
    MILESTONE = "milestone"


@dataclass
class Achievement:
    """An achievement worth noting."""
    type: AchievementType
    description: str
    impact: str
    severity: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.type.value}: {self.description}"


# Celebration phrases by achievement type (European restraint - not over the top)
CELEBRATIONS = {
    AchievementType.BUG_FOUND: [
        "Found a bug",
        "Caught an issue",
        "Spotted a problem",
        "Uncovered an issue",
        "Found something",
        "Identified a defect",
        "Flagged an issue",
        "Detected a problem",
    ],
    AchievementType.CRITICAL_BUG: [
        "Found a critical issue",
        "Caught a significant bug",
        "Identified a major problem",
        "This one's important",
        "Big catch here",
        "Glad we found this",
        "This would've been bad in production",
        "Critical find",
    ],
    AchievementType.EDGE_CASE: [
        "Nice catch",
        "Good edge case",
        "Interesting scenario",
        "Sharp eye",
        "Smart scenario",
        "Clever test case",
        "This is the kind of thing that slips through",
        "Non-obvious but important",
    ],
    AchievementType.COVERAGE_COMPLETE: [
        "Coverage complete",
        "All scenarios covered",
        "Testing thorough",
        "We've got good coverage",
        "Feature well-tested now",
        "Comprehensive testing done",
        "All bases covered",
        "Solid test suite",
    ],
    AchievementType.SECURITY_ISSUE: [
        "Security concern identified",
        "Potential vulnerability found",
        "Security improvement needed",
        "Security gap detected",
        "This could be exploited",
        "Security team should see this",
        "Attack vector identified",
        "Defense needed here",
    ],
    AchievementType.ACCESSIBILITY_ISSUE: [
        "Accessibility issue found",
        "A11y improvement needed",
        "Usability gap identified",
        "Some users would struggle here",
        "Screen reader issue",
        "Keyboard navigation gap",
        "WCAG concern",
        "Inclusive design opportunity",
    ],
    AchievementType.PERFORMANCE_ISSUE: [
        "Performance concern noted",
        "Speed improvement possible",
        "Optimization opportunity",
        "This could be faster",
        "Performance bottleneck",
        "Users might notice slowness",
        "Room for optimization",
        "Efficiency concern",
    ],
    AchievementType.TEST_PASSED: [
        "Test passed",
        "Working as expected",
        "Verified",
        "All good here",
        "Confirmed working",
        "No issues found",
        "Looks correct",
        "Behaves properly",
    ],
    AchievementType.MILESTONE: [
        "Milestone reached",
        "Good progress",
        "Moving forward",
        "Making headway",
        "Progress made",
        "Step complete",
        "Checkpoint reached",
        "On track",
    ],
}

# Impact phrases
IMPACT_PHRASES = {
    "high": [
        "This could affect many users",
        "This is production-impacting",
        "This needs attention",
        "High priority fix needed",
        "This is user-facing",
        "Could cause support tickets",
        "Potential P1 issue",
        "Fix before release",
    ],
    "medium": [
        "Worth fixing soon",
        "Should be addressed",
        "Needs review",
        "Put it on the backlog",
        "Not urgent but important",
        "Should be fixed this sprint",
        "Good candidate for next iteration",
        "Track this one",
    ],
    "low": [
        "Minor improvement possible",
        "Nice to fix",
        "Low priority",
        "When there's time",
        "Polish opportunity",
        "Not blocking",
        "Backlog candidate",
        "Future enhancement",
    ],
}

# Phrases for summarizing sessions
SUMMARY_INTROS = [
    "Here's what we found:",
    "Testing complete. Summary:",
    "Analysis done. Results:",
    "Here's the rundown:",
    "Quick summary:",
    "What we uncovered:",
    "The findings:",
    "Session results:",
]

# Phrases for when nothing was found
NOTHING_FOUND = [
    "No issues found. Looking good!",
    "Clean bill of health.",
    "Nothing concerning here.",
    "All tests passing.",
    "Feature looks solid.",
    "No problems detected.",
    "Everything checks out.",
    "Looks good to ship.",
]


class Celebrator:
    """
    Generates appropriate celebrations for achievements.

    Usage:
        celebrator = Celebrator()

        # Celebrate finding a bug
        msg = celebrator.celebrate(Achievement(
            type=AchievementType.BUG_FOUND,
            description="Login accepts empty password",
            impact="high"
        ))

        # Quick celebration
        msg = celebrator.bug_found("XSS in search field", severity="critical")
    """

    def __init__(self, enthusiasm_level: int = 1):
        """
        Initialize celebrator.

        Args:
            enthusiasm_level: 0=minimal, 1=normal, 2=excited
        """
        self.enthusiasm = min(max(enthusiasm_level, 0), 2)

    def celebrate(self, achievement: Achievement) -> str:
        """Generate a celebration message for an achievement."""
        base = random.choice(CELEBRATIONS.get(achievement.type, ["Good find"]))

        # Add description
        message = f"{base}: {achievement.description}"

        # Add impact if meaningful
        if achievement.impact and achievement.impact in IMPACT_PHRASES:
            impact = random.choice(IMPACT_PHRASES[achievement.impact])
            message += f". {impact}."

        # Add enthusiasm based on level
        if self.enthusiasm >= 2 and achievement.type in [
            AchievementType.CRITICAL_BUG,
            AchievementType.SECURITY_ISSUE,
        ]:
            message += " 🎯"  # Only emoji for really significant finds

        return message

    def bug_found(
        self,
        description: str,
        severity: str = "medium",
    ) -> str:
        """Quick celebration for finding a bug."""
        if severity == "critical":
            achievement_type = AchievementType.CRITICAL_BUG
            impact = "high"
        else:
            achievement_type = AchievementType.BUG_FOUND
            impact = severity

        return self.celebrate(Achievement(
            type=achievement_type,
            description=description,
            impact=impact,
            severity=severity,
        ))

    def edge_case_found(self, description: str) -> str:
        """Celebrate finding an edge case."""
        return self.celebrate(Achievement(
            type=AchievementType.EDGE_CASE,
            description=description,
            impact="medium",
        ))

    def security_issue(
        self,
        description: str,
        severity: str = "high",
    ) -> str:
        """Celebrate finding a security issue."""
        return self.celebrate(Achievement(
            type=AchievementType.SECURITY_ISSUE,
            description=description,
            impact="high",
            severity=severity,
        ))

    def coverage_complete(
        self,
        feature: str,
        test_count: int,
    ) -> str:
        """Celebrate completing test coverage."""
        return self.celebrate(Achievement(
            type=AchievementType.COVERAGE_COMPLETE,
            description=f"{feature} - {test_count} tests",
            impact="medium",
        ))

    def milestone(
        self,
        description: str,
        progress: float,  # 0.0 to 1.0
    ) -> str:
        """Celebrate reaching a milestone."""
        pct = int(progress * 100)
        return self.celebrate(Achievement(
            type=AchievementType.MILESTONE,
            description=f"{description} ({pct}%)",
            impact="low",
        ))

    def summary(
        self,
        bugs_found: int,
        tests_generated: int,
        critical_issues: int = 0,
    ) -> str:
        """Generate a summary celebration."""
        if bugs_found == 0 and tests_generated == 0:
            return random.choice(NOTHING_FOUND)

        intro = random.choice(SUMMARY_INTROS)
        parts = []

        if tests_generated > 0:
            if tests_generated == 1:
                parts.append("1 test case")
            else:
                parts.append(f"{tests_generated} test cases")

        if bugs_found > 0:
            if bugs_found == 1:
                parts.append("1 issue identified")
            else:
                parts.append(f"{bugs_found} issues identified")

        if critical_issues > 0:
            if critical_issues == 1:
                parts.append("1 critical")
            else:
                parts.append(f"{critical_issues} critical")

        summary = f"{intro} {', '.join(parts)}."

        # Add contextual advice
        if critical_issues > 0:
            advice = random.choice([
                " Address critical items first.",
                " Critical issues should be top priority.",
                " Start with the critical ones.",
                " The critical findings need immediate attention.",
            ])
            summary += advice
        elif tests_generated > 10:
            advice = random.choice([
                " Good comprehensive coverage.",
                " Solid test coverage achieved.",
                " That's thorough testing.",
                " Well-covered feature.",
            ])
            summary += advice
        elif bugs_found > 5:
            advice = random.choice([
                " Several areas need attention.",
                " Multiple issues to review.",
                " Worth a thorough look at these.",
            ])
            summary += advice

        return summary


# Convenience function
def celebrate(
    achievement_type: AchievementType,
    description: str,
    impact: str = "medium",
) -> str:
    """Quick celebration helper."""
    celebrator = Celebrator()
    return celebrator.celebrate(Achievement(
        type=achievement_type,
        description=description,
        impact=impact,
    ))
