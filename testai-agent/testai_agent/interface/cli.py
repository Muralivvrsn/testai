"""
TestAI Agent - Human-Like CLI Interface

A CLI that behaves like a Senior European QA Consultant:
- Asks clarifying questions before making assumptions
- Shows visible thinking process
- Presents results in beautiful, executive-ready format
- Uses rich markdown formatting
"""

import asyncio
import sys
from typing import Optional, List, Callable
from enum import Enum

# Color codes for terminal
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    # Foreground
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"

    # Background
    BG_BLACK = "\033[40m"
    BG_BLUE = "\033[44m"
    BG_CYAN = "\033[46m"


def c(text: str, *colors) -> str:
    """Apply colors to text."""
    prefix = ''.join(colors)
    return f"{prefix}{text}{Colors.RESET}"


def box(text: str, width: int = 60, char: str = "═") -> str:
    """Create a box around text."""
    top = f"╔{char * (width - 2)}╗"
    bottom = f"╚{char * (width - 2)}╝"
    lines = text.split('\n')

    boxed = [top]
    for line in lines:
        padding = width - 4 - len(line)
        boxed.append(f"║ {line}{' ' * max(0, padding)} ║")
    boxed.append(bottom)

    return '\n'.join(boxed)


class ConsoleUI:
    """
    Rich console UI for the QA Agent.

    Provides:
    - Styled output (colors, boxes, headers)
    - Progress indicators
    - Interactive prompts
    - Markdown rendering
    """

    def __init__(self):
        self.indent = 0
        self._thinking_active = False

    def print_header(self):
        """Print the application header."""
        header = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   🧪  TestAI Agent - Cognitive QA System                        ║
║   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                         ║
║   Senior European QA Consultant                                  ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
        print(c(header, Colors.BRIGHT_CYAN))

    def print_status(self, brain_status: dict, gateway_status: dict):
        """Print system status."""
        print(c("\n📊 System Status", Colors.BOLD, Colors.WHITE))
        print(c("─" * 50, Colors.DIM))

        # Brain status
        brain_ready = brain_status.get("ready", False)
        chunks = brain_status.get("knowledge_chunks", 0)
        brain_color = Colors.GREEN if brain_ready else Colors.RED
        brain_icon = "✓" if brain_ready else "✗"
        print(f"  {c(brain_icon, brain_color)} Brain (RAG): {c(brain_status.get('status', 'Unknown'), brain_color)} ({chunks} knowledge chunks)")

        # Gateway status
        for provider, status in gateway_status.items():
            prov_status = status.get("status", "Unknown")
            prov_color = Colors.GREEN if prov_status == "Active" else Colors.YELLOW
            prov_icon = "✓" if prov_status == "Active" else "○"
            calls = status.get("calls", "0/0")
            print(f"  {c(prov_icon, prov_color)} {provider.upper()}: {c(prov_status, prov_color)} ({calls} calls)")

        print()

    def print_thinking(self, thought: str):
        """Print a thinking indicator."""
        icon = "💭" if not self._thinking_active else "  "
        print(c(f"  {icon} {thought}", Colors.DIM, Colors.ITALIC))
        self._thinking_active = True

    def end_thinking(self):
        """End thinking mode."""
        self._thinking_active = False
        print()

    def print_question(self, question: str, options: List[str], context: str = None):
        """Print a clarifying question."""
        print(c("\n❓ Clarifying Question", Colors.BOLD, Colors.YELLOW))
        print(c("─" * 50, Colors.DIM))

        if context:
            print(c(f"  Context: {context}", Colors.DIM))
            print()

        print(c(f"  {question}", Colors.WHITE))
        print()

        for i, opt in enumerate(options, 1):
            print(f"    {c(str(i), Colors.CYAN)}. {opt}")

        print()

    def prompt_choice(self, prompt: str = "Your choice", default: int = None) -> int:
        """Prompt for a numeric choice."""
        default_str = f" [{default}]" if default else ""
        try:
            choice = input(c(f"  {prompt}{default_str}: ", Colors.CYAN))
            if not choice and default:
                return default
            return int(choice)
        except (ValueError, EOFError):
            return default or 1

    def prompt_text(self, prompt: str, default: str = None) -> str:
        """Prompt for text input."""
        default_str = f" [{default}]" if default else ""
        try:
            text = input(c(f"  {prompt}{default_str}: ", Colors.CYAN))
            return text if text else (default or "")
        except EOFError:
            return default or ""

    def print_risk_assessment(self, risk_assessment):
        """Print a formatted risk assessment."""
        print(c("\n🎯 Risk Assessment", Colors.BOLD, Colors.WHITE))
        print(c("═" * 60, Colors.DIM))

        # Overall risk with color coding
        risk_colors = {
            "Critical": Colors.BRIGHT_RED,
            "High": Colors.RED,
            "Medium": Colors.YELLOW,
            "Low": Colors.GREEN
        }
        risk_level = risk_assessment.overall_risk.value
        risk_color = risk_colors.get(risk_level, Colors.WHITE)

        print(f"\n  Feature: {c(risk_assessment.feature, Colors.BOLD)}")
        print(f"  Overall Risk: {c(risk_level, risk_color, Colors.BOLD)}")

        # Security risks
        if risk_assessment.security_risks:
            print(c("\n  🔒 Security Risks:", Colors.BOLD, Colors.RED))
            for risk in risk_assessment.security_risks:
                print(f"     • {risk}")

        # Functional risks
        if risk_assessment.functional_risks:
            print(c("\n  ⚙️  Functional Risks:", Colors.BOLD, Colors.YELLOW))
            for risk in risk_assessment.functional_risks:
                print(f"     • {risk}")

        # UI risks
        if risk_assessment.ui_risks:
            print(c("\n  🎨 UI/UX Risks:", Colors.BOLD, Colors.MAGENTA))
            for risk in risk_assessment.ui_risks:
                print(f"     • {risk}")

        # Recommendations
        if risk_assessment.recommendations:
            print(c("\n  ✅ Recommendations:", Colors.BOLD, Colors.GREEN))
            for rec in risk_assessment.recommendations:
                print(f"     • {rec}")

        print()

    def print_test_case(self, test_case):
        """Print a single test case."""
        # Category colors
        cat_colors = {
            "Security": Colors.RED,
            "Functional": Colors.BLUE,
            "UI/UX": Colors.MAGENTA,
            "Input Validation": Colors.YELLOW,
            "Edge Cases": Colors.CYAN,
        }

        cat = test_case.category.value
        cat_color = cat_colors.get(cat, Colors.WHITE)

        # Risk level indicator
        risk_icons = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢"
        }
        risk_icon = risk_icons.get(test_case.risk_level.value, "⚪")

        print(c(f"\n  ┌─ {test_case.id}: {test_case.title}", Colors.BOLD))
        print(c(f"  │", Colors.DIM))
        print(f"  │  {c('Category:', Colors.DIM)} {c(cat, cat_color)}")
        print(f"  │  {c('Risk:', Colors.DIM)} {risk_icon} {test_case.risk_level.value}")

        if test_case.preconditions:
            print(f"  │  {c('Preconditions:', Colors.DIM)}")
            for pre in test_case.preconditions:
                print(f"  │    • {pre}")

        print(f"  │  {c('Steps:', Colors.DIM)}")
        for i, step in enumerate(test_case.steps, 1):
            print(f"  │    {i}. {step}")

        print(f"  │  {c('Expected:', Colors.DIM)} {test_case.expected_result}")
        print(c(f"  │  📚 {test_case.source_citation}", Colors.DIM, Colors.ITALIC))
        print(c(f"  └{'─' * 58}", Colors.DIM))

    def print_test_plan(self, test_plan):
        """Print a complete test plan."""
        print(c("\n" + "═" * 60, Colors.BRIGHT_CYAN))
        print(c(f"  📋 TEST PLAN: {test_plan.feature.upper()}", Colors.BOLD, Colors.BRIGHT_CYAN))
        print(c("═" * 60, Colors.BRIGHT_CYAN))

        # Risk assessment
        self.print_risk_assessment(test_plan.risk_assessment)

        # Summary
        print(c("\n📈 Test Summary", Colors.BOLD, Colors.WHITE))
        print(c("─" * 40, Colors.DIM))
        print(f"  Total Test Cases: {c(str(test_plan.total_tests), Colors.BOLD)}")

        print(c("\n  By Category:", Colors.DIM))
        for cat, count in test_plan.by_category.items():
            print(f"    • {cat}: {count}")

        print(c("\n  By Risk Level:", Colors.DIM))
        for risk, count in test_plan.by_risk.items():
            print(f"    • {risk}: {count}")

        # Test cases grouped by category
        categories_order = ["Security", "Functional", "Input Validation", "UI/UX", "Edge Cases"]

        by_cat = {}
        for tc in test_plan.test_cases:
            cat = tc.category.value
            if cat not in by_cat:
                by_cat[cat] = []
            by_cat[cat].append(tc)

        for cat in categories_order:
            if cat in by_cat:
                print(c(f"\n{'─' * 60}", Colors.DIM))
                print(c(f"  📂 {cat.upper()} TESTS ({len(by_cat[cat])})", Colors.BOLD))
                print(c(f"{'─' * 60}", Colors.DIM))

                for tc in by_cat[cat]:
                    self.print_test_case(tc)

        # Citations
        print(c(f"\n{'─' * 60}", Colors.DIM))
        print(c("  📚 SOURCES REFERENCED", Colors.BOLD, Colors.DIM))
        print(c(f"{'─' * 60}", Colors.DIM))
        for cite in sorted(set(test_plan.all_citations)):
            print(f"  • {cite}")

        print(c("\n" + "═" * 60, Colors.BRIGHT_CYAN))

    def print_success(self, message: str):
        """Print a success message."""
        print(c(f"\n  ✓ {message}", Colors.GREEN, Colors.BOLD))

    def print_error(self, message: str):
        """Print an error message."""
        print(c(f"\n  ✗ {message}", Colors.RED, Colors.BOLD))

    def print_warning(self, message: str):
        """Print a warning message."""
        print(c(f"\n  ⚠ {message}", Colors.YELLOW))

    def print_info(self, message: str):
        """Print an info message."""
        print(c(f"\n  ℹ {message}", Colors.CYAN))

    def print_divider(self, char: str = "─", length: int = 60):
        """Print a divider line."""
        print(c(char * length, Colors.DIM))

    def print_help(self):
        """Print help information."""
        help_text = """
Commands:
  test <feature>    Generate test plan for a feature
  analyze <feature> Analyze feature without generating tests
  status            Show system status
  help              Show this help message
  exit              Exit the application

Examples:
  test login page with email and password
  test checkout flow with credit card payment
  test user registration form
  analyze search functionality
"""
        print(c(help_text, Colors.DIM))

    def animate_progress(self, message: str, duration: float = 0.5):
        """Show a brief progress animation."""
        import time
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        end_time = time.time() + duration
        i = 0

        while time.time() < end_time:
            sys.stdout.write(f"\r  {c(frames[i % len(frames)], Colors.CYAN)} {message}")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1

        sys.stdout.write(f"\r  {c('✓', Colors.GREEN)} {message}\n")
        sys.stdout.flush()


def create_thinking_callback(ui: ConsoleUI) -> Callable[[str], None]:
    """Create a thinking callback for the Cortex."""
    def callback(thought: str):
        ui.print_thinking(thought)
    return callback
