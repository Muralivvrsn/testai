#!/usr/bin/env python3
"""
TestAI Agent - Interactive CLI

A rich, human-like command-line interface for test generation.
Feels like chatting with a QA colleague.

Features:
- Visible thinking process
- Clarifying questions
- Citation-backed test generation
- Multiple output formats (executive, technical, QA)
- Session persistence
- Playwright code generation

Usage:
    python interactive_cli.py              # Interactive mode
    python interactive_cli.py --quick "Login Page"  # Quick generation
"""

import asyncio
import sys
import os
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

# Import components
from pipeline import TestPipeline, PipelineResult
from generators.cited_generator import (
    create_generator_for_page_type,
    CitedTestGenerator,
)
from generators.executive_summary import StakeholderType
from personality.qa_consultant import QAConsultantPersonality
from interface.thinking_stream import create_stream
from conversation.memory import ConversationalMemory, MemoryType
from conversation.persistence import SessionStore
from executors import create_executor, OutputFormat


# ─────────────────────────────────────────────────────────────────
# Terminal Colors (European Minimal Aesthetic)
# ─────────────────────────────────────────────────────────────────

class Colors:
    """Terminal colors - subtle, not shouty."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"

    # Muted colors
    BLUE = "\033[38;5;67m"      # Slate blue
    GREEN = "\033[38;5;108m"    # Sage green
    YELLOW = "\033[38;5;179m"   # Muted gold
    RED = "\033[38;5;167m"      # Dusty rose
    GRAY = "\033[38;5;245m"     # Warm gray
    CYAN = "\033[38;5;73m"      # Soft cyan

    @classmethod
    def disable(cls):
        """Disable colors for non-terminal output."""
        for attr in dir(cls):
            if not attr.startswith("_") and attr.isupper():
                setattr(cls, attr, "")


# Check if we're in a terminal
if not sys.stdout.isatty():
    Colors.disable()


# ─────────────────────────────────────────────────────────────────
# Interactive CLI
# ─────────────────────────────────────────────────────────────────

class InteractiveCLI:
    """
    Rich interactive CLI for TestAI Agent.

    Features:
    - Natural conversation flow
    - Visible thinking process
    - Clarifying questions before generation
    - Multiple stakeholder views
    - Session persistence
    - Test code export
    """

    def __init__(self, verbose: bool = True):
        """Initialize the CLI."""
        self.verbose = verbose

        # Components
        self.pipeline = TestPipeline(verbose=False)
        self.consultant = QAConsultantPersonality()
        self.memory = ConversationalMemory()
        self.session_store = SessionStore()
        self.executor = create_executor()

        # State
        self.current_tests: List[Dict[str, Any]] = []
        self.current_feature: Optional[str] = None
        self.current_page_type: Optional[str] = None
        self.current_result: Optional[PipelineResult] = None
        self.stakeholder: StakeholderType = StakeholderType.EXECUTIVE

    # ─────────────────────────────────────────────────────────────
    # Output Methods
    # ─────────────────────────────────────────────────────────────

    def _print(self, text: str = "", color: str = "", end: str = "\n"):
        """Print with optional color."""
        print(f"{color}{text}{Colors.RESET}", end=end)

    def _print_header(self):
        """Print the header."""
        print()
        self._print("━" * 55, Colors.GRAY)
        self._print("  ╭─────────────────────────────────╮", Colors.BLUE)
        self._print("  │       TestAI Agent              │", Colors.BLUE + Colors.BOLD)
        self._print("  │   Your QA colleague, always on  │", Colors.BLUE)
        self._print("  ╰─────────────────────────────────╯", Colors.BLUE)
        self._print("━" * 55, Colors.GRAY)
        print()

    def _print_thinking(self, text: str):
        """Print thinking message."""
        self._print(f"  💭 {text}", Colors.DIM)

    def _print_agent(self, text: str):
        """Print agent response."""
        self._print(f"\n{Colors.CYAN}┃{Colors.RESET} {text}")

    def _print_success(self, text: str):
        """Print success message."""
        self._print(f"\n  {Colors.GREEN}✓{Colors.RESET} {text}")

    def _print_warning(self, text: str):
        """Print warning message."""
        self._print(f"\n  {Colors.YELLOW}⚠{Colors.RESET} {text}")

    def _print_error(self, text: str):
        """Print error message."""
        self._print(f"\n  {Colors.RED}✗{Colors.RESET} {text}")

    def _print_section(self, title: str):
        """Print section header."""
        print()
        self._print(f"─── {title} ", Colors.GRAY, end="")
        self._print("─" * (45 - len(title)), Colors.GRAY)
        print()

    def _prompt(self, text: str = "You") -> str:
        """Get user input."""
        self._print(f"\n{Colors.GRAY}{text}{Colors.RESET}: ", end="")
        try:
            return input().strip()
        except (EOFError, KeyboardInterrupt):
            return "quit"

    # ─────────────────────────────────────────────────────────────
    # Core Methods
    # ─────────────────────────────────────────────────────────────

    def greet(self):
        """Show greeting."""
        greeting = self.consultant.greet()
        self._print_agent(greeting)
        self._print(f"\n  {Colors.DIM}Type /help for commands, or just tell me what to test.{Colors.RESET}")

    def show_help(self):
        """Show help text."""
        self._print_section("Commands")

        commands = [
            ("/test <feature>", "Generate tests for a feature"),
            ("/quick <feature>", "Quick generation (skip questions)"),
            ("/view <audience>", "Change view (executive/product/engineering/qa)"),
            ("/export <format>", "Export tests (json/pytest/typescript)"),
            ("/tests", "Show current tests"),
            ("/details", "Show detailed test cases"),
            ("/status", "Show session status"),
            ("/sessions", "List saved sessions"),
            ("/load <id>", "Load a saved session"),
            ("/clear", "Clear screen"),
            ("/verbose", "Toggle verbose mode"),
            ("/help", "Show this help"),
            ("/quit", "Exit"),
        ]

        for cmd, desc in commands:
            self._print(f"  {Colors.CYAN}{cmd:20}{Colors.RESET} {desc}")

        self._print("\n  Or just describe what you want to test in plain English.", Colors.DIM)

    async def ask_clarifying_questions(self) -> Dict[str, str]:
        """Ask clarifying questions before generating tests."""
        if not self.current_page_type:
            return {}

        questions = self.consultant.get_clarifying_questions(
            user_input=self.current_feature or "",
            detected_page_type=self.current_page_type,
            max_questions=3,
        )

        if not questions:
            return {}

        self._print_section("Quick Questions")
        self._print_agent("Before I generate tests, a few quick questions to ensure accuracy:")
        print()

        answers = {}
        for i, q in enumerate(questions, 1):
            self._print(f"  {Colors.BOLD}{i}.{Colors.RESET} {q.question}")
            if q.options:
                self._print(f"     {Colors.DIM}Options: {', '.join(q.options)}{Colors.RESET}")
            if q.default:
                self._print(f"     {Colors.DIM}Default: {q.default}{Colors.RESET}")

            answer = self._prompt(f"  Answer (or press Enter for default)")
            answers[q.question] = answer if answer else (q.default or "")

        return answers

    async def generate_tests(
        self,
        feature: str,
        skip_clarify: bool = False,
    ):
        """Generate tests for a feature."""
        self.current_feature = feature

        # Detect page type
        self._print_thinking("Understanding your request...")
        self.current_page_type = self.pipeline._detect_page_type(feature)
        self._print_thinking(f"Detected page type: {self.current_page_type}")

        # Ask clarifying questions (unless skipped)
        clarifications = {}
        if not skip_clarify:
            clarifications = await self.ask_clarifying_questions()

        # Show generation progress
        self._print_section("Generating Tests")

        def thinking_callback(phase: str, message: str):
            self._print_thinking(f"[{phase}] {message}")

        self.pipeline.thinking_callback = thinking_callback

        # Run pipeline
        self._print_thinking("Searching knowledge base...")
        result = await self.pipeline.run(
            feature=feature,
            page_type=self.current_page_type,
            stakeholder=self.stakeholder.value,
            skip_clarify=True,  # We already asked
            clarifications=clarifications,
        )

        self.current_result = result
        self.current_tests = result.tests

        # Store in memory
        self.memory.set_working_context(
            feature=feature,
            page_type=self.current_page_type,
        )
        self.memory.remember(MemoryType.TEST, f"Generated {len(result.tests)} tests for {feature}")

        # Show results
        if result.success:
            self._print_success(f"Generated {len(result.tests)} test cases")
            self._show_summary(result)
        else:
            self._print_error("Failed to generate tests")
            if result.context.errors:
                for err in result.context.errors:
                    self._print(f"  {Colors.RED}•{Colors.RESET} {err}")

    def _show_summary(self, result: PipelineResult):
        """Show test generation summary."""
        self._print_section("Summary")

        # Ship decision with color
        decision_colors = {
            "go": Colors.GREEN,
            "caution": Colors.YELLOW,
            "no_go": Colors.RED,
        }
        color = decision_colors.get(result.ship_decision, Colors.GRAY)

        self._print(f"  Ship Decision: {color}{result.ship_decision.upper()}{Colors.RESET}")
        self._print(f"  Risk Level: {result.risk_level}")
        self._print(f"  Tests: {len(result.tests)}")
        self._print(f"  Citations: {', '.join(result.citations)}")

        # Category breakdown
        categories = {}
        for test in result.tests:
            cat = test.get("category", "other")
            categories[cat] = categories.get(cat, 0) + 1

        if categories:
            self._print("\n  By Category:")
            for cat, count in categories.items():
                self._print(f"    • {cat}: {count}")

        self._print(f"\n  {Colors.DIM}Type /tests to see test list, /details for full tests{Colors.RESET}")

    def show_tests(self, detailed: bool = False):
        """Show current tests."""
        if not self.current_tests:
            self._print_agent("No tests generated yet. Tell me what to test!")
            return

        self._print_section(f"Tests for {self.current_feature or 'Feature'}")

        for i, test in enumerate(self.current_tests, 1):
            priority = test.get("priority", "medium").upper()
            priority_colors = {
                "CRITICAL": Colors.RED,
                "HIGH": Colors.YELLOW,
                "MEDIUM": Colors.CYAN,
                "LOW": Colors.GREEN,
            }
            p_color = priority_colors.get(priority, Colors.GRAY)

            self._print(f"\n  {Colors.BOLD}{test.get('id', f'TC-{i:03d}')}{Colors.RESET}: {test.get('title', 'Test')}")
            self._print(f"    {p_color}[{priority}]{Colors.RESET} {test.get('category', 'functional')}")

            if detailed:
                self._print(f"\n    {Colors.DIM}Description:{Colors.RESET}")
                self._print(f"    {test.get('description', 'N/A')}")

                if test.get("steps"):
                    self._print(f"\n    {Colors.DIM}Steps:{Colors.RESET}")
                    for j, step in enumerate(test["steps"], 1):
                        self._print(f"      {j}. {step}")

                if test.get("expected_result"):
                    self._print(f"\n    {Colors.DIM}Expected:{Colors.RESET}")
                    self._print(f"    {test['expected_result']}")

                if test.get("citations"):
                    self._print(f"\n    {Colors.DIM}Sources:{Colors.RESET}")
                    for cit in test["citations"]:
                        self._print(f"      📖 [{cit.get('section_id', '?')}] {cit.get('section_title', 'Unknown')}")

    def export_tests(self, format: str = "json"):
        """Export tests to file."""
        if not self.current_tests:
            self._print_warning("No tests to export. Generate some first!")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        feature_slug = (self.current_feature or "tests").lower().replace(" ", "_")[:20]

        if format == "json":
            filename = f"{feature_slug}_{timestamp}.json"
            with open(filename, "w") as f:
                json.dump({
                    "feature": self.current_feature,
                    "page_type": self.current_page_type,
                    "generated_at": timestamp,
                    "test_count": len(self.current_tests),
                    "tests": self.current_tests,
                }, f, indent=2)

        elif format in ["pytest", "python"]:
            filename = f"test_{feature_slug}_{timestamp}.py"
            from executors import generate_pytest_suite
            code = generate_pytest_suite(self.current_tests, f"test_{feature_slug}")
            with open(filename, "w") as f:
                f.write(code)

        elif format in ["typescript", "ts"]:
            filename = f"test_{feature_slug}_{timestamp}.spec.ts"
            code_parts = []
            for test in self.current_tests:
                code_parts.append(self.executor.generate_code(test, OutputFormat.TYPESCRIPT))
            with open(filename, "w") as f:
                f.write("\n\n".join(code_parts))

        else:
            self._print_error(f"Unknown format: {format}. Use json, pytest, or typescript.")
            return

        self._print_success(f"Exported {len(self.current_tests)} tests to {filename}")

    def show_status(self):
        """Show session status."""
        self._print_section("Session Status")

        self._print(f"  Feature: {self.current_feature or 'None'}")
        self._print(f"  Page Type: {self.current_page_type or 'None'}")
        self._print(f"  Tests Generated: {len(self.current_tests)}")
        self._print(f"  Stakeholder View: {self.stakeholder.value}")
        self._print(f"  Verbose: {'On' if self.verbose else 'Off'}")

        if self.current_result:
            self._print(f"\n  Last Generation:")
            self._print(f"    Ship Decision: {self.current_result.ship_decision}")
            self._print(f"    Execution Time: {self.current_result.execution_time:.2f}s")

    def show_sessions(self):
        """List saved sessions."""
        sessions = self.session_store.list_sessions()

        if not sessions:
            self._print_agent("No saved sessions yet.")
            return

        self._print_section("Saved Sessions")

        for s in sessions[:10]:  # Show last 10
            feature = s.feature_focus or "Unknown"
            self._print(f"  • {Colors.CYAN}{s.session_id[:20]}...{Colors.RESET}")
            self._print(f"    Feature: {feature}, Tests: {s.test_count}")

    def load_session(self, session_id: str):
        """Load a saved session."""
        # Find matching session
        sessions = self.session_store.list_sessions()
        matching = [s for s in sessions if s.session_id.startswith(session_id)]

        if not matching:
            self._print_error(f"Session not found: {session_id}")
            return

        session = matching[0]
        loaded = self.session_store.load_session(session.session_id)

        if loaded:
            self.memory = loaded
            self.current_feature = loaded.working.current_feature
            self.current_page_type = loaded.working.current_page_type
            self._print_success(f"Loaded session: {session.session_id[:30]}...")
            if self.current_feature:
                self._print(f"  Feature: {self.current_feature}")
        else:
            self._print_error("Failed to load session")

    def change_view(self, audience: str):
        """Change stakeholder view."""
        try:
            self.stakeholder = StakeholderType(audience.lower())
            self._print_success(f"Switched to {audience} view")

            # Re-show summary if we have results
            if self.current_result:
                self._print(f"\n{Colors.DIM}Regenerating summary for {audience} view...{Colors.RESET}")
                self._show_summary(self.current_result)
        except ValueError:
            self._print_error(f"Unknown audience: {audience}")
            self._print(f"  {Colors.DIM}Valid options: executive, product, engineering, qa{Colors.RESET}")

    async def process_input(self, text: str) -> bool:
        """
        Process user input.

        Returns:
            True to continue, False to exit
        """
        text = text.strip()
        if not text:
            return True

        # Handle commands
        if text.startswith("/"):
            parts = text[1:].split(maxsplit=1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            if cmd in ["quit", "exit", "q"]:
                self._save_session()
                self._print_agent("Happy testing! See you next time. 👋")
                return False

            elif cmd == "help":
                self.show_help()

            elif cmd == "test":
                if args:
                    await self.generate_tests(args, skip_clarify=False)
                else:
                    self._print_warning("Please specify a feature: /test <feature>")

            elif cmd == "quick":
                if args:
                    await self.generate_tests(args, skip_clarify=True)
                else:
                    self._print_warning("Please specify a feature: /quick <feature>")

            elif cmd == "tests":
                self.show_tests(detailed=False)

            elif cmd == "details":
                self.show_tests(detailed=True)

            elif cmd == "export":
                self.export_tests(args or "json")

            elif cmd == "view":
                if args:
                    self.change_view(args)
                else:
                    self._print(f"  Current view: {self.stakeholder.value}")

            elif cmd == "status":
                self.show_status()

            elif cmd == "sessions":
                self.show_sessions()

            elif cmd == "load":
                if args:
                    self.load_session(args)
                else:
                    self._print_warning("Please specify session ID: /load <id>")

            elif cmd == "verbose":
                self.verbose = not self.verbose
                self._print_success(f"Verbose mode {'on' if self.verbose else 'off'}")

            elif cmd == "clear":
                os.system("clear" if os.name != "nt" else "cls")
                self._print_header()

            else:
                self._print_warning(f"Unknown command: /{cmd}")
                self._print(f"  {Colors.DIM}Type /help for available commands{Colors.RESET}")

        # Natural language input
        else:
            # Try to understand intent
            text_lower = text.lower()

            if any(word in text_lower for word in ["test", "generate", "create", "check"]):
                # Extract feature from text
                feature = text
                for prefix in ["test ", "generate tests for ", "create tests for ", "check "]:
                    if text_lower.startswith(prefix):
                        feature = text[len(prefix):]
                        break

                await self.generate_tests(feature, skip_clarify=False)

            elif "?" in text:
                # It's a question
                self._print_agent("That's a good question. Here's what I can help with:")
                self._print(f"  {Colors.DIM}• Generate comprehensive test cases for any feature{Colors.RESET}")
                self._print(f"  {Colors.DIM}• Export tests as JSON, Pytest, or TypeScript{Colors.RESET}")
                self._print(f"  {Colors.DIM}• Provide executive, product, or technical views{Colors.RESET}")
                self._print(f"\n  {Colors.DIM}Just tell me what you want to test!{Colors.RESET}")

            else:
                self._print_agent(f"I understand you're interested in '{text}'.")
                self._print(f"  {Colors.DIM}Would you like me to generate tests for it?{Colors.RESET}")
                self._print(f"  {Colors.DIM}Type '/test {text}' or just say 'yes'{Colors.RESET}")

        return True

    def _save_session(self):
        """Save current session."""
        if self.memory.conversation_history:
            session_id = self.session_store.save_session(self.memory)
            self._print(f"\n{Colors.DIM}💾 Session saved ({session_id[:20]}...){Colors.RESET}")

    async def run(self):
        """Run the interactive CLI."""
        self._print_header()
        self.greet()

        running = True
        while running:
            try:
                text = self._prompt()
                running = await self.process_input(text)

            except KeyboardInterrupt:
                print()
                self._print_warning("Interrupted. Type /quit to exit.")

            except Exception as e:
                self._print_error(f"Error: {e}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()


# ─────────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────────

async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="TestAI Agent - Interactive CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python interactive_cli.py                    # Interactive mode
  python interactive_cli.py --quick "Login"    # Quick generation
  python interactive_cli.py --test "Checkout"  # With clarifying questions
        """,
    )
    parser.add_argument("--quick", "-q", help="Quick generation (skip questions)")
    parser.add_argument("--test", "-t", help="Generate tests with questions")
    parser.add_argument("--export", "-e", help="Export format (json/pytest/typescript)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    cli = InteractiveCLI(verbose=args.verbose)

    if args.quick:
        # Quick mode
        cli._print_header()
        await cli.generate_tests(args.quick, skip_clarify=True)
        if args.export:
            cli.export_tests(args.export)

    elif args.test:
        # Test with questions
        cli._print_header()
        await cli.generate_tests(args.test, skip_clarify=False)
        if args.export:
            cli.export_tests(args.export)

    else:
        # Interactive mode
        await cli.run()


if __name__ == "__main__":
    asyncio.run(main())
