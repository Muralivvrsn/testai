"""
TestAI Agent - User Journey Simulator

Simulates realistic user journeys through applications
with decision points and outcome tracking.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Callable
import random


class JourneyOutcome(Enum):
    """Possible journey outcomes."""
    SUCCESS = "success"
    FAILURE = "failure"
    ABANDONED = "abandoned"
    BLOCKED = "blocked"
    ERROR = "error"


class StepType(Enum):
    """Types of journey steps."""
    NAVIGATION = "navigation"
    INPUT = "input"
    ACTION = "action"
    VERIFICATION = "verification"
    DECISION = "decision"
    WAIT = "wait"


class UserBehavior(Enum):
    """User behavior patterns."""
    EFFICIENT = "efficient"  # Straight to goal
    EXPLORATORY = "exploratory"  # Clicks around
    HESITANT = "hesitant"  # Pauses, goes back
    DISTRACTED = "distracted"  # Opens other tabs
    FRUSTRATED = "frustrated"  # Repeats actions
    CAREFUL = "careful"  # Reads everything


@dataclass
class JourneyStep:
    """A single step in a user journey."""
    step_id: str
    step_type: StepType
    name: str
    description: str
    action: str
    target: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    expected_result: Optional[str] = None
    duration_ms: int = 0
    outcome: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DecisionPoint:
    """A decision point in the journey."""
    decision_id: str
    name: str
    options: List[str]
    probabilities: Dict[str, float]
    depends_on: Optional[str] = None


@dataclass
class UserJourney:
    """A complete user journey."""
    journey_id: str
    name: str
    description: str
    goal: str
    persona: str
    behavior: UserBehavior
    steps: List[JourneyStep]
    decision_points: List[DecisionPoint]
    total_duration_ms: int
    outcome: JourneyOutcome
    completion_rate: float
    friction_points: List[str]


class JourneySimulator:
    """
    Simulates user journeys through applications.

    Features:
    - Behavior-driven simulation
    - Decision point modeling
    - Friction detection
    - Outcome prediction
    - Journey optimization suggestions
    """

    # Journey templates
    JOURNEY_TEMPLATES = {
        "registration": {
            "name": "User Registration",
            "goal": "Create new account",
            "steps": [
                ("navigation", "Visit homepage", "Navigate to site"),
                ("action", "Click signup", "Click registration button"),
                ("input", "Fill email", "Enter email address"),
                ("input", "Fill password", "Enter password"),
                ("input", "Fill profile", "Enter profile details"),
                ("action", "Submit form", "Submit registration form"),
                ("verification", "Verify email", "Check email confirmation"),
                ("action", "Confirm email", "Click confirmation link"),
                ("verification", "Check success", "Verify account created"),
            ],
            "decisions": [
                ("social_login", ["continue_manual", "use_google", "use_facebook"], {"continue_manual": 0.6, "use_google": 0.3, "use_facebook": 0.1}),
                ("newsletter", ["skip", "subscribe"], {"skip": 0.7, "subscribe": 0.3}),
            ],
        },
        "checkout": {
            "name": "Checkout Process",
            "goal": "Complete purchase",
            "steps": [
                ("navigation", "View cart", "Navigate to cart"),
                ("verification", "Review items", "Check cart contents"),
                ("action", "Proceed checkout", "Click checkout button"),
                ("input", "Shipping address", "Enter shipping details"),
                ("decision", "Shipping method", "Select shipping option"),
                ("input", "Payment info", "Enter payment details"),
                ("verification", "Review order", "Check order summary"),
                ("action", "Place order", "Confirm purchase"),
                ("verification", "Confirmation", "Verify order placed"),
            ],
            "decisions": [
                ("guest_checkout", ["login", "guest"], {"login": 0.4, "guest": 0.6}),
                ("shipping", ["standard", "express", "overnight"], {"standard": 0.7, "express": 0.25, "overnight": 0.05}),
                ("save_payment", ["yes", "no"], {"yes": 0.3, "no": 0.7}),
            ],
        },
        "login": {
            "name": "User Login",
            "goal": "Access account",
            "steps": [
                ("navigation", "Visit login", "Navigate to login page"),
                ("input", "Enter credentials", "Input username and password"),
                ("action", "Submit login", "Click login button"),
                ("verification", "Check access", "Verify dashboard access"),
            ],
            "decisions": [
                ("remember_me", ["yes", "no"], {"yes": 0.6, "no": 0.4}),
                ("forgot_password", ["continue", "reset"], {"continue": 0.95, "reset": 0.05}),
            ],
        },
        "search_purchase": {
            "name": "Search and Purchase",
            "goal": "Find and buy product",
            "steps": [
                ("navigation", "Visit site", "Navigate to homepage"),
                ("input", "Search product", "Enter search query"),
                ("verification", "View results", "Check search results"),
                ("action", "Select product", "Click on product"),
                ("verification", "View details", "Check product details"),
                ("decision", "Add to cart", "Decide to purchase"),
                ("action", "Add item", "Add to shopping cart"),
                ("navigation", "Go to cart", "Navigate to cart"),
                ("action", "Checkout", "Proceed to checkout"),
            ],
            "decisions": [
                ("filter_results", ["no_filter", "price", "rating", "brand"], {"no_filter": 0.4, "price": 0.3, "rating": 0.2, "brand": 0.1}),
                ("compare", ["direct_buy", "compare_first"], {"direct_buy": 0.7, "compare_first": 0.3}),
            ],
        },
    }

    # Behavior modifiers
    BEHAVIOR_MODIFIERS = {
        UserBehavior.EFFICIENT: {
            "extra_steps_probability": 0.1,
            "back_probability": 0.05,
            "pause_probability": 0.1,
            "abandon_probability": 0.05,
            "time_multiplier": 0.8,
        },
        UserBehavior.EXPLORATORY: {
            "extra_steps_probability": 0.5,
            "back_probability": 0.2,
            "pause_probability": 0.3,
            "abandon_probability": 0.1,
            "time_multiplier": 1.5,
        },
        UserBehavior.HESITANT: {
            "extra_steps_probability": 0.3,
            "back_probability": 0.4,
            "pause_probability": 0.5,
            "abandon_probability": 0.2,
            "time_multiplier": 2.0,
        },
        UserBehavior.FRUSTRATED: {
            "extra_steps_probability": 0.4,
            "back_probability": 0.3,
            "pause_probability": 0.2,
            "abandon_probability": 0.3,
            "time_multiplier": 1.3,
        },
    }

    def __init__(self, seed: Optional[int] = None):
        """Initialize the journey simulator."""
        if seed:
            random.seed(seed)
        self._journey_counter = 0
        self._step_counter = 0

    def simulate(
        self,
        journey_type: str,
        behavior: UserBehavior = UserBehavior.EFFICIENT,
        persona: str = "default_user",
        failure_probability: float = 0.1,
    ) -> UserJourney:
        """Simulate a user journey."""
        template = self.JOURNEY_TEMPLATES.get(
            journey_type,
            self._get_generic_template()
        )

        self._journey_counter += 1
        modifiers = self.BEHAVIOR_MODIFIERS.get(
            behavior,
            self.BEHAVIOR_MODIFIERS[UserBehavior.EFFICIENT]
        )

        # Generate steps
        steps = []
        decision_points = []
        friction_points = []
        total_duration = 0
        outcome = JourneyOutcome.SUCCESS
        steps_completed = 0

        for step_def in template["steps"]:
            step_type, name, description = step_def

            self._step_counter += 1
            duration = self._calculate_step_duration(step_type, modifiers)

            step = JourneyStep(
                step_id=f"STEP-{self._step_counter:05d}",
                step_type=StepType(step_type) if step_type in [e.value for e in StepType] else StepType.ACTION,
                name=name,
                description=description,
                action=description,
                duration_ms=duration,
            )

            # Check for behavior-based modifications
            if random.random() < modifiers["back_probability"]:
                friction_points.append(f"User went back at: {name}")
                duration += self._calculate_step_duration("navigation", modifiers)

            if random.random() < modifiers["pause_probability"]:
                friction_points.append(f"User paused at: {name}")
                duration += random.randint(2000, 10000)

            # Check for abandonment
            if random.random() < modifiers["abandon_probability"]:
                outcome = JourneyOutcome.ABANDONED
                step.outcome = "abandoned"
                steps.append(step)
                break

            # Check for failure
            if random.random() < failure_probability:
                outcome = JourneyOutcome.FAILURE
                step.outcome = "failed"
                step.error = self._generate_failure_reason(step_type)
                friction_points.append(f"Failure at: {name} - {step.error}")
                steps.append(step)
                break

            step.outcome = "completed"
            steps.append(step)
            steps_completed += 1
            total_duration += duration

        # Process decision points
        for decision_def in template.get("decisions", []):
            decision_id, options, probs = decision_def
            decision = DecisionPoint(
                decision_id=decision_id,
                name=decision_id.replace("_", " ").title(),
                options=options,
                probabilities=probs,
            )
            decision_points.append(decision)

        completion_rate = steps_completed / len(template["steps"]) if template["steps"] else 0

        return UserJourney(
            journey_id=f"JRN-{self._journey_counter:05d}",
            name=template["name"],
            description=f"{template['name']} simulation",
            goal=template["goal"],
            persona=persona,
            behavior=behavior,
            steps=steps,
            decision_points=decision_points,
            total_duration_ms=total_duration,
            outcome=outcome,
            completion_rate=completion_rate,
            friction_points=friction_points,
        )

    def simulate_batch(
        self,
        journey_type: str,
        count: int,
        behavior_distribution: Optional[Dict[UserBehavior, float]] = None,
    ) -> List[UserJourney]:
        """Simulate multiple journeys for statistical analysis."""
        if behavior_distribution is None:
            behavior_distribution = {
                UserBehavior.EFFICIENT: 0.4,
                UserBehavior.EXPLORATORY: 0.2,
                UserBehavior.HESITANT: 0.2,
                UserBehavior.FRUSTRATED: 0.1,
                UserBehavior.CAREFUL: 0.1,
            }

        journeys = []
        for _ in range(count):
            # Select behavior based on distribution
            behavior = self._select_behavior(behavior_distribution)
            journey = self.simulate(journey_type, behavior)
            journeys.append(journey)

        return journeys

    def analyze_journeys(
        self,
        journeys: List[UserJourney],
    ) -> Dict[str, Any]:
        """Analyze a set of journeys for insights."""
        if not journeys:
            return {"error": "No journeys to analyze"}

        # Outcome distribution
        outcome_counts = {}
        for journey in journeys:
            outcome = journey.outcome.value
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1

        # Completion rates
        completion_rates = [j.completion_rate for j in journeys]
        avg_completion = sum(completion_rates) / len(completion_rates)

        # Duration statistics
        durations = [j.total_duration_ms for j in journeys]
        avg_duration = sum(durations) / len(durations)

        # Friction points
        all_friction = []
        for journey in journeys:
            all_friction.extend(journey.friction_points)

        friction_counts = {}
        for point in all_friction:
            friction_counts[point] = friction_counts.get(point, 0) + 1

        top_friction = sorted(
            friction_counts.items(),
            key=lambda x: -x[1]
        )[:5]

        # Behavior vs outcome
        behavior_outcomes = {}
        for journey in journeys:
            behavior = journey.behavior.value
            if behavior not in behavior_outcomes:
                behavior_outcomes[behavior] = {"success": 0, "total": 0}
            behavior_outcomes[behavior]["total"] += 1
            if journey.outcome == JourneyOutcome.SUCCESS:
                behavior_outcomes[behavior]["success"] += 1

        behavior_success_rates = {
            b: data["success"] / data["total"] if data["total"] > 0 else 0
            for b, data in behavior_outcomes.items()
        }

        return {
            "total_journeys": len(journeys),
            "outcome_distribution": outcome_counts,
            "success_rate": outcome_counts.get("success", 0) / len(journeys),
            "avg_completion_rate": avg_completion,
            "avg_duration_ms": avg_duration,
            "top_friction_points": top_friction,
            "behavior_success_rates": behavior_success_rates,
        }

    def suggest_improvements(
        self,
        analysis: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        """Suggest improvements based on journey analysis."""
        suggestions = []

        # Low success rate
        success_rate = analysis.get("success_rate", 0)
        if success_rate < 0.8:
            suggestions.append({
                "issue": "Low overall success rate",
                "value": f"{success_rate:.1%}",
                "suggestion": "Review flow for blocking issues",
            })

        # Low completion rate
        completion_rate = analysis.get("avg_completion_rate", 0)
        if completion_rate < 0.7:
            suggestions.append({
                "issue": "Low completion rate",
                "value": f"{completion_rate:.1%}",
                "suggestion": "Simplify journey steps or add progress indicators",
            })

        # High duration
        avg_duration = analysis.get("avg_duration_ms", 0)
        if avg_duration > 120000:  # 2 minutes
            suggestions.append({
                "issue": "Long journey duration",
                "value": f"{avg_duration / 1000:.1f}s",
                "suggestion": "Reduce number of steps or enable shortcuts",
            })

        # Friction points
        friction = analysis.get("top_friction_points", [])
        for point, count in friction[:3]:
            suggestions.append({
                "issue": f"Friction point: {point}",
                "value": f"{count} occurrences",
                "suggestion": "Improve UX at this step",
            })

        # Behavior-specific issues
        behavior_rates = analysis.get("behavior_success_rates", {})
        for behavior, rate in behavior_rates.items():
            if rate < 0.5:
                suggestions.append({
                    "issue": f"Low success for {behavior} users",
                    "value": f"{rate:.1%}",
                    "suggestion": f"Add support features for {behavior} behavior",
                })

        return suggestions

    def _calculate_step_duration(
        self,
        step_type: str,
        modifiers: Dict[str, Any],
    ) -> int:
        """Calculate step duration based on type and behavior."""
        base_durations = {
            "navigation": 2000,
            "input": 5000,
            "action": 1500,
            "verification": 3000,
            "decision": 8000,
            "wait": 10000,
        }

        base = base_durations.get(step_type, 3000)
        multiplier = modifiers.get("time_multiplier", 1.0)

        # Add some variance
        variance = random.uniform(0.8, 1.2)

        return int(base * multiplier * variance)

    def _generate_failure_reason(self, step_type: str) -> str:
        """Generate a failure reason for a step."""
        reasons = {
            "navigation": ["Page not found", "Timeout", "Redirect loop"],
            "input": ["Validation failed", "Field not found", "Input rejected"],
            "action": ["Button disabled", "Server error", "Session expired"],
            "verification": ["Element not visible", "Wrong content", "Missing element"],
        }

        type_reasons = reasons.get(step_type, ["Unknown error"])
        return random.choice(type_reasons)

    def _select_behavior(
        self,
        distribution: Dict[UserBehavior, float],
    ) -> UserBehavior:
        """Select behavior based on probability distribution."""
        rand = random.random()
        cumulative = 0

        for behavior, prob in distribution.items():
            cumulative += prob
            if rand < cumulative:
                return behavior

        return UserBehavior.EFFICIENT

    def _get_generic_template(self) -> Dict[str, Any]:
        """Get a generic journey template."""
        return {
            "name": "Generic Journey",
            "goal": "Complete task",
            "steps": [
                ("navigation", "Start", "Begin journey"),
                ("action", "Main action", "Perform primary action"),
                ("verification", "Verify", "Check result"),
            ],
            "decisions": [],
        }

    def get_available_journeys(self) -> List[str]:
        """Get available journey types."""
        return list(self.JOURNEY_TEMPLATES.keys())

    def format_journey(self, journey: UserJourney) -> str:
        """Format journey as readable text."""
        lines = [
            "=" * 60,
            f"  USER JOURNEY: {journey.journey_id}",
            "=" * 60,
            "",
            f"  Name: {journey.name}",
            f"  Goal: {journey.goal}",
            f"  Persona: {journey.persona}",
            f"  Behavior: {journey.behavior.value}",
            "",
            f"  Outcome: {journey.outcome.value.upper()}",
            f"  Completion: {journey.completion_rate:.1%}",
            f"  Duration: {journey.total_duration_ms / 1000:.1f}s",
            "",
        ]

        # Steps
        lines.extend([
            "-" * 60,
            "  STEPS",
            "-" * 60,
        ])

        status_icons = {
            "completed": "✅",
            "failed": "❌",
            "abandoned": "⏸️",
        }

        for step in journey.steps:
            icon = status_icons.get(step.outcome, "⚪")
            lines.append(f"  {icon} {step.name} ({step.duration_ms}ms)")
            if step.error:
                lines.append(f"     Error: {step.error}")

        # Friction points
        if journey.friction_points:
            lines.extend([
                "",
                "-" * 60,
                "  FRICTION POINTS",
                "-" * 60,
            ])
            for point in journey.friction_points:
                lines.append(f"  ⚠️ {point}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_journey_simulator(seed: Optional[int] = None) -> JourneySimulator:
    """Create a journey simulator instance."""
    return JourneySimulator(seed)
