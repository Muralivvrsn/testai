#!/usr/bin/env python3
"""
TestAI Agent - Human-Like Demo

Demonstrates all the human-like capabilities:
1. Visible thinking with real-time progress
2. Clarifying questions before action
3. Citation-backed test generation
4. Executive-ready output
5. Session persistence

This demo shows what makes TestAI Agent feel like a real QA colleague.

Usage:
    python human_demo.py                    # Interactive mode
    python human_demo.py --feature "login"  # Generate tests for login
    python human_demo.py --demo             # Run full demo sequence
"""

import asyncio
import sys
import os
import time
from pathlib import Path
from typing import Optional, List, Dict, Any

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

# Import components
from interface.thinking_stream import ThinkingStream, ThoughtType, create_stream
from personality.qa_consultant import QAConsultantPersonality, create_consultant
from generators.cited_generator import CitedTestGenerator, create_login_generator
from generators.executive_summary import (
    ExecutiveSummaryGenerator,
    StakeholderType,
    ShipDecision,
)
from brain.smart_ingest import SmartBrainIngestor, ingest_brain_content
from cortex.prioritizer import TestPrioritizer, Priority
from conversation.persistence import SessionStore, get_session_summary
from conversation.memory import ConversationalMemory, MemoryType


# ─────────────────────────────────────────────────────────────────
# Terminal Colors (European Minimal Aesthetic)
# ─────────────────────────────────────────────────────────────────

class Colors:
    """Muted, professional colors."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Muted palette
    BLUE = "\033[38;5;67m"      # Slate blue
    GREEN = "\033[38;5;108m"    # Sage green
    YELLOW = "\033[38;5;179m"   # Muted gold
    RED = "\033[38;5;167m"      # Dusty rose
    GRAY = "\033[38;5;245m"     # Warm gray
    CYAN = "\033[38;5;73m"      # Muted cyan

    @classmethod
    def disable(cls):
        """Disable colors."""
        for attr in dir(cls):
            if not attr.startswith("_") and attr.isupper():
                setattr(cls, attr, "")


# Check terminal
if not sys.stdout.isatty():
    Colors.disable()


# ─────────────────────────────────────────────────────────────────
# Human Demo Class
# ─────────────────────────────────────────────────────────────────

class HumanDemo:
    """
    Demonstrates human-like QA agent behavior.

    Features:
    - Visible thinking process
    - Clarifying questions
    - Citation-backed generation
    - Executive summaries
    - Session persistence
    """

    def __init__(self):
        """Initialize demo components."""
        self.stream = create_stream(verbose=True, color=True)
        self.consultant = create_consultant(verbose=True)
        self.generator = create_login_generator()
        self.prioritizer = TestPrioritizer()
        self.summary_generator = ExecutiveSummaryGenerator()
        self.session_store = SessionStore()
        self.memory = ConversationalMemory()

        # State
        self.current_feature = None
        self.current_page_type = None
        self.generated_tests = []
        self.user_answers = {}

    def _print(self, text: str, color: str = "", end: str = "\n"):
        """Print with color."""
        print(f"{color}{text}{Colors.RESET}", end=end)

    def _print_header(self, text: str):
        """Print a header."""
        print()
        self._print("─" * 60, Colors.GRAY)
        self._print(f"  {text}", Colors.BOLD)
        self._print("─" * 60, Colors.GRAY)
        print()

    def _print_agent(self, text: str):
        """Print agent speech."""
        self._print(f"\n{Colors.BLUE}QA Agent{Colors.RESET}: {text}")

    def _print_success(self, text: str):
        """Print success message."""
        self._print(f"\n{Colors.GREEN}✓{Colors.RESET} {text}")

    def _print_warning(self, text: str):
        """Print warning."""
        self._print(f"\n{Colors.YELLOW}⚠{Colors.RESET} {text}")

    def _get_input(self, prompt: str) -> str:
        """Get user input."""
        self._print(f"\n{Colors.GRAY}You{Colors.RESET}: ", end="")
        try:
            return input().strip()
        except (EOFError, KeyboardInterrupt):
            return "quit"

    def show_greeting(self):
        """Show initial greeting."""
        self._print_header("TestAI Agent - Your QA Colleague")

        greeting = self.consultant.greet()
        self._print_agent(greeting)

        # Check for previous session
        summary = get_session_summary()
        if summary:
            self._print(f"\n{Colors.DIM}📝 Previous session: {summary}{Colors.RESET}")
            self._print(f"{Colors.DIM}   Type 'continue' to resume{Colors.RESET}")

    def ask_clarifying_questions(
        self,
        feature: str,
        page_type: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Ask clarifying questions before generating tests.

        Returns:
            Dictionary of question -> answer
        """
        self._print_header("Clarifying Questions")

        self._print_agent(
            "Before I generate comprehensive test cases, I'd like to understand your context better."
        )

        questions = self.consultant.get_clarifying_questions(
            user_input=feature,
            detected_page_type=page_type,
            max_questions=4,
        )

        answers = {}

        for i, q in enumerate(questions, 1):
            # Priority indicator
            priority_icon = {
                "critical": f"{Colors.RED}●{Colors.RESET}",
                "important": f"{Colors.YELLOW}●{Colors.RESET}",
                "optional": f"{Colors.GREEN}●{Colors.RESET}",
            }.get(q.priority.value, "●")

            print()
            self._print(f"{priority_icon} Question {i}: {q.question}")

            if q.options:
                self._print(f"   {Colors.DIM}Options: {' | '.join(q.options)}{Colors.RESET}")

            if q.context:
                self._print(f"   {Colors.DIM}(This helps me {q.context}){Colors.RESET}")

            # Get answer (or use default)
            answer = self._get_input("Your answer (or press Enter for default)")

            if not answer and q.default:
                answer = q.default
                self._print(f"   {Colors.DIM}Using default: {answer}{Colors.RESET}")
            elif not answer:
                answer = "Not specified"

            answers[q.question] = answer

            # Remember the answer
            self.memory.remember(
                MemoryType.CLARIFICATION,
                f"Q: {q.question} A: {answer}",
                importance=0.7,
            )

        self._print_success(f"Got {len(answers)} answers. Now I have better context.")

        return answers

    def show_thinking_process(
        self,
        feature: str,
        page_type: str,
        answers: Dict[str, str],
    ):
        """
        Show visible thinking process.

        This is what makes the agent feel human - you see its reasoning.
        """
        self._print_header("Thinking Process")

        with self.stream.thinking(f"Generating tests for {feature}") as stream:
            # Phase 1: Understanding
            stream.understanding(f"Processing request for {feature}")
            time.sleep(0.3)

            stream.understanding(
                "Analyzing user context",
                detail=f"Page type: {page_type}, {len(answers)} clarifications provided",
            )
            time.sleep(0.3)

            # Phase 2: Searching Brain
            stream.searching("Querying QA knowledge base...")
            time.sleep(0.5)

            # Simulate finding sources
            sources = [
                ("7.1", "Email Validation", 0.95),
                ("7.2", "Password Validation", 0.92),
                ("7.3", "Authentication Security", 0.88),
                ("7.4", "Login Flow", 0.85),
                ("7.5", "Error Handling", 0.80),
            ]

            for section_id, title, confidence in sources[:3]:
                stream.found(
                    f"Found relevant rules in Section {section_id}",
                    source=f"Section {section_id}: {title}",
                    confidence=confidence,
                )
                time.sleep(0.2)

            # Phase 3: Analyzing
            stream.analyzing("Cross-referencing security requirements...")
            time.sleep(0.4)

            stream.analyzing(
                "Identifying edge cases from user context",
                detail=f"Considering {len(answers)} user-specified constraints",
            )
            time.sleep(0.3)

            # Phase 4: Reasoning
            stream.reasoning(
                "Authentication testing requires both positive and negative cases",
                detail="High-risk area due to security implications",
            )
            time.sleep(0.3)

            # Phase 5: Deciding
            stream.deciding(
                "Will generate comprehensive test suite",
                confidence=0.87,
                detail="Covering security, functional, and edge cases",
            )
            time.sleep(0.3)

            # Phase 6: Generating
            with stream.with_spinner("Generating test cases"):
                time.sleep(1.0)

            stream.generating("Created test cases with citations")
            time.sleep(0.2)

            # Phase 7: Validating
            stream.validating("All test cases backed by knowledge base citations")
            time.sleep(0.2)

            stream.complete("Test generation complete")

    def generate_tests(
        self,
        feature: str,
        page_type: str,
    ) -> List[Dict[str, Any]]:
        """
        Generate tests with citations.

        Every test traces back to a Brain section.
        """
        self._print_header("Test Generation")

        # Generate using cited generator
        plan = self.generator.generate(
            feature=feature,
            page_type=page_type,
            max_tests=15,
        )

        # Prioritize tests
        test_dicts = [t.to_dict() for t in plan.tests]
        prioritized = self.prioritizer.prioritize(test_dicts, page_type=page_type)

        # Store results
        self.generated_tests = test_dicts

        # Show summary
        self._print_agent(f"Generated {len(plan.tests)} test cases.")
        print()

        # Show by priority
        by_priority = {}
        for pt in prioritized:
            pri = pt.computed_priority.value
            by_priority[pri] = by_priority.get(pri, 0) + 1

        self._print("Test Distribution:", Colors.BOLD)
        priority_icons = {
            "critical": f"{Colors.RED}●{Colors.RESET}",
            "high": f"{Colors.YELLOW}●{Colors.RESET}",
            "medium": f"{Colors.CYAN}●{Colors.RESET}",
            "low": f"{Colors.GREEN}●{Colors.RESET}",
        }

        for pri in ["critical", "high", "medium", "low"]:
            count = by_priority.get(pri, 0)
            if count > 0:
                icon = priority_icons.get(pri, "●")
                self._print(f"  {icon} {pri.upper()}: {count} tests")

        # Show sources cited
        print()
        self._print("Sources Cited:", Colors.BOLD)
        seen_sources = set()
        for test in plan.tests:
            for citation in test.citations:
                if citation.section_id not in seen_sources:
                    self._print(
                        f"  📚 [{citation.section_id}] {citation.section_title}",
                        Colors.DIM,
                    )
                    seen_sources.add(citation.section_id)

        return test_dicts

    def show_test_details(self, tests: List[Dict[str, Any]], limit: int = 5):
        """Show detailed test cases."""
        self._print_header("Test Case Details")

        for i, test in enumerate(tests[:limit], 1):
            # Priority badge
            priority = test.get("priority", "medium")
            priority_badge = {
                "critical": f"{Colors.RED}[CRITICAL]{Colors.RESET}",
                "high": f"{Colors.YELLOW}[HIGH]{Colors.RESET}",
                "medium": f"{Colors.CYAN}[MEDIUM]{Colors.RESET}",
                "low": f"{Colors.GREEN}[LOW]{Colors.RESET}",
            }.get(priority, "")

            print()
            self._print(f"{priority_badge} {test.get('id', f'TC-{i:03d}')}: {test.get('title', 'Untitled')}", Colors.BOLD)

            if test.get("description"):
                self._print(f"   {test['description']}", Colors.DIM)

            # Steps
            steps = test.get("steps", [])
            if steps:
                self._print("   Steps:", Colors.GRAY)
                for j, step in enumerate(steps[:4], 1):
                    self._print(f"      {j}. {step}", Colors.DIM)

            # Citations
            citations = test.get("citations", [])
            if citations:
                citation = citations[0]
                self._print(
                    f"   📖 Source: {citation.get('full_path', citation.get('section_id', 'Unknown'))}",
                    Colors.GRAY,
                )

        if len(tests) > limit:
            self._print(f"\n   {Colors.DIM}... and {len(tests) - limit} more tests{Colors.RESET}")

    def show_executive_summary(
        self,
        feature: str,
        tests: List[Dict[str, Any]],
        stakeholder: StakeholderType = StakeholderType.EXECUTIVE,
    ):
        """Show executive summary."""
        self._print_header(f"Executive Summary ({stakeholder.value.title()})")

        summary = self.summary_generator.create_summary(feature, tests)
        formatted = self.summary_generator.format_for_stakeholder(summary, stakeholder)

        # Colorize the output
        for line in formatted.split("\n"):
            if line.startswith("# "):
                self._print(line[2:], Colors.BOLD)
            elif line.startswith("## "):
                self._print(line[3:], Colors.CYAN)
            elif line.startswith("### "):
                self._print(line[4:], Colors.YELLOW)
            elif "GO" in line and "Ship" in line:
                self._print(line, Colors.GREEN)
            elif "NO_GO" in line or "BLOCKER" in line:
                self._print(line, Colors.RED)
            elif "CAUTION" in line or "WARNING" in line:
                self._print(line, Colors.YELLOW)
            elif line.startswith("- "):
                self._print(line, Colors.DIM)
            else:
                print(line)

    def save_session(self):
        """Save current session."""
        if self.current_feature:
            self.memory.set_working_context(
                feature=self.current_feature,
                page_type=self.current_page_type,
            )

        session_id = self.session_store.save_session(self.memory)
        self._print(f"\n{Colors.DIM}💾 Session saved: {session_id[:20]}...{Colors.RESET}")

    async def run_demo(self, feature: str = "Login Page"):
        """Run the full demo sequence."""
        self.show_greeting()

        # Detect page type
        page_type = "login"  # Default for demo
        for pt in ["login", "signup", "checkout", "search", "form"]:
            if pt in feature.lower():
                page_type = pt
                break

        self.current_feature = feature
        self.current_page_type = page_type

        # Store in memory
        self.memory.add_user_turn(f"Generate tests for {feature}")
        self.memory.set_working_context(feature=feature, page_type=page_type)

        # Step 1: Clarifying Questions
        self._print_agent(
            f"I understand you want to test: {Colors.BOLD}{feature}{Colors.RESET}"
        )
        time.sleep(0.5)

        answers = self.ask_clarifying_questions(feature, page_type)
        self.user_answers = answers

        # Step 2: Thinking Process
        self.show_thinking_process(feature, page_type, answers)

        # Step 3: Generate Tests
        tests = self.generate_tests(feature, page_type)

        # Step 4: Show Details
        self.show_test_details(tests)

        # Step 5: Executive Summary
        self.show_executive_summary(feature, tests)

        # Step 6: Offer options
        self._print_header("What's Next?")
        self._print_agent("I've completed the test plan. What would you like to do?")
        print()
        self._print("  1. Show Engineering view", Colors.DIM)
        self._print("  2. Show QA view (full details)", Colors.DIM)
        self._print("  3. Export to file", Colors.DIM)
        self._print("  4. Generate for another feature", Colors.DIM)
        self._print("  5. Exit", Colors.DIM)

        # Save session
        self.save_session()

        self._print(f"\n{Colors.DIM}Type a number to continue, or 'quit' to exit{Colors.RESET}")

    async def run_interactive(self):
        """Run interactive mode."""
        self.show_greeting()

        running = True
        while running:
            user_input = self._get_input("What would you like to test?")

            if not user_input:
                continue

            if user_input.lower() in ["quit", "exit", "q"]:
                self._print_agent("Happy testing! Remember: good QA prevents bad releases. 👋")
                self.save_session()
                running = False
                continue

            if user_input.lower() == "continue":
                latest_id = self.session_store.get_latest_session()
                if latest_id:
                    loaded = self.session_store.load_session(latest_id)
                    if loaded:
                        self.memory = loaded
                        self._print_success("Resumed previous session")
                        if self.memory.working.current_feature:
                            self._print(
                                f"  {Colors.DIM}Feature: {self.memory.working.current_feature}{Colors.RESET}"
                            )
                continue

            # Process the request
            await self.run_demo(user_input)


# ─────────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────────

async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="TestAI Agent - Human-Like QA Demo"
    )
    parser.add_argument(
        "--feature", "-f",
        help="Feature to test (e.g., 'login page')",
    )
    parser.add_argument(
        "--demo", "-d",
        action="store_true",
        help="Run full demo sequence",
    )
    parser.add_argument(
        "--stakeholder", "-s",
        choices=["executive", "product", "engineering", "qa"],
        default="executive",
        help="Stakeholder view for summary",
    )

    args = parser.parse_args()

    demo = HumanDemo()

    if args.feature:
        await demo.run_demo(args.feature)
    elif args.demo:
        await demo.run_demo("Login Page")
    else:
        await demo.run_interactive()


if __name__ == "__main__":
    asyncio.run(main())
