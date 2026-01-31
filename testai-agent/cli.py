"""
TestAI Agent - Command Line Interface

A CLI that feels like chatting with a QA colleague.
European design: clean, minimal, purposeful.

Enhanced with:
- Conversational memory across interactions
- Visible thinking with progress indicators
- Human-like clarification questions
- Executive-ready output formatting
- Real-time usage tracking

Usage:
    python cli.py                    # Interactive mode
    python cli.py --analyze URL      # Analyze a URL
    python cli.py --test "feature"   # Generate tests for feature
"""

import asyncio
import sys
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
import time

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from conversation.interface import Conversation, ConversationState, greet, acknowledge_task
from conversation.responses import (
    HumanResponse, format_test_cases, format_page_analysis,
    format_progress, format_error, OutputStyle
)
from conversation.memory import ConversationalMemory, MemoryType, extract_entities
from conversation.persistence import SessionStore, get_session_summary
from personality.tone import Confidence
from personality.human_clarifier import HumanClarifier, QuestionContext
from interface.thinking_display import ThinkingDisplay, ThinkingPhase
from interface.usage_dashboard import UsageDashboard, ProviderName


# Colors for terminal output (European minimal aesthetic)
class Colors:
    """Terminal colors - subtle, not shouty."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Muted colors
    BLUE = "\033[38;5;67m"      # Slate blue
    GREEN = "\033[38;5;108m"    # Sage green
    YELLOW = "\033[38;5;179m"   # Muted gold
    RED = "\033[38;5;167m"      # Dusty rose
    GRAY = "\033[38;5;245m"     # Warm gray

    @classmethod
    def disable(cls):
        """Disable colors (for non-terminal output)."""
        for attr in dir(cls):
            if not attr.startswith("_") and attr.isupper():
                setattr(cls, attr, "")


# Check if we're in a terminal
if not sys.stdout.isatty():
    Colors.disable()


class QAInterface:
    """
    The human-facing QA interface.

    Handles:
    - Natural conversation flow
    - Progressive information disclosure
    - Smart prompts and suggestions
    - Error recovery
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the interface.

        Args:
            api_key: DeepSeek API key (uses env if not provided)
        """
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "sk-c104455631bb433b801fc4a16042419c")
        self.conversation = Conversation()
        self.agent = None
        self._initialized = False

        # Enhanced components
        self.memory = ConversationalMemory()
        self.clarifier = HumanClarifier()
        self.thinking = ThinkingDisplay(verbose=True)
        self.dashboard = UsageDashboard()
        self.session_store = SessionStore()

        # State
        self.current_tests = []
        self.current_page = None
        self.verbose = False
        self._session_resumed = False

    def _print(self, text: str, color: str = "", end: str = "\n"):
        """Print with optional color."""
        print(f"{color}{text}{Colors.RESET}", end=end)

    def _print_agent(self, text: str):
        """Print agent response."""
        self._print(f"\n{Colors.BLUE}QA Agent{Colors.RESET}: {text}")

    def _print_thinking(self, text: str):
        """Print agent thinking (subtle)."""
        self._print(f"{Colors.DIM}  💭 {text}{Colors.RESET}")

    def _print_success(self, text: str):
        """Print success message."""
        self._print(f"\n{Colors.GREEN}✓{Colors.RESET} {text}")

    def _print_warning(self, text: str):
        """Print warning message."""
        self._print(f"\n{Colors.YELLOW}⚠{Colors.RESET} {text}")

    def _print_error(self, text: str):
        """Print error message."""
        self._print(f"\n{Colors.RED}✗{Colors.RESET} {text}")

    def _print_header(self):
        """Print the header."""
        print()
        self._print("─" * 50, Colors.GRAY)
        self._print("  TestAI Agent", Colors.BOLD)
        self._print("  Your QA colleague that never sleeps", Colors.DIM)
        self._print("─" * 50, Colors.GRAY)
        print()

    def _print_prompt(self) -> str:
        """Print prompt and get input."""
        self._print(f"\n{Colors.GRAY}You{Colors.RESET}: ", end="")
        try:
            return input().strip()
        except (EOFError, KeyboardInterrupt):
            return "quit"

    async def _ensure_initialized(self):
        """Initialize the agent if needed."""
        if self._initialized:
            return

        self._print_thinking("Loading QA knowledge base...")

        try:
            from agent import create_agent

            self.agent = create_agent(
                api_key=self.api_key,
                budget_limit=0.50,  # $0.50 max for CLI session
            )

            # Try to load brain
            brain_paths = [
                "./QA_BRAIN.md",
                "../QA_BRAIN.md",
                "../../QA_BRAIN.md",
            ]

            for path in brain_paths:
                if Path(path).exists():
                    self._print_thinking(f"Found knowledge base at {path}")
                    result = await self.agent.load_brain(path)
                    if result.get("status") in ["success", "already_loaded"]:
                        chunks = result.get("chunks", self.agent.brain._chunk_count)
                        self._print_success(f"Loaded {chunks} pieces of QA knowledge")
                    break
            else:
                self._print_warning("QA_BRAIN.md not found. Working with built-in knowledge only.")

            self._initialized = True

        except Exception as e:
            self._print_error(f"Failed to initialize: {e}")
            raise

    def _parse_command(self, text: str) -> tuple[str, List[str]]:
        """Parse a command from user input."""
        text = text.strip()

        # Check for commands
        if text.startswith("/"):
            parts = text[1:].split(maxsplit=1)
            cmd = parts[0].lower()
            args = parts[1].split() if len(parts) > 1 else []
            return cmd, args

        return "", [text]

    async def _handle_command(self, cmd: str, args: List[str]) -> bool:
        """
        Handle a command.

        Returns:
            True if should continue, False to exit
        """
        if cmd in ["quit", "exit", "q"]:
            self._print_agent("Alright, happy testing! 👋")
            return False

        elif cmd == "help":
            self._show_help()

        elif cmd == "status":
            await self._show_status()

        elif cmd == "clear":
            os.system("clear" if os.name != "nt" else "cls")
            self._print_header()

        elif cmd == "verbose":
            self.verbose = not self.verbose
            self._print_agent(f"Verbose mode {'on' if self.verbose else 'off'}")

        elif cmd in ["tests", "show"]:
            await self._show_tests()

        elif cmd == "export":
            await self._export_tests(args[0] if args else "tests.json")

        elif cmd == "sessions":
            self._show_sessions()

        else:
            self._print_agent(f"Unknown command: /{cmd}. Try /help")

        return True

    def _show_help(self):
        """Show help text."""
        help_text = """
Available commands:
  /help     - Show this help
  /status   - Show agent status
  /tests    - Show generated tests
  /export   - Export tests to file
  /verbose  - Toggle verbose mode
  /sessions - List saved sessions
  /clear    - Clear screen
  /quit     - Exit

Session commands:
  continue  - Resume previous session (at startup)

Or just tell me what you want to test!

Examples:
  "Test the login page"
  "I need tests for checkout flow"
  "What security tests should I run for user registration?"
        """
        self._print(help_text, Colors.DIM)

    async def _show_status(self):
        """Show agent status."""
        await self._ensure_initialized()

        status = self.agent.get_status()
        self._print_agent("Here's where we stand:")
        print()
        self._print(f"  Knowledge base: {status.brain_chunks} rules loaded", Colors.DIM)
        self._print(f"  API budget: ${status.budget_remaining:.4f} remaining", Colors.DIM)
        self._print(f"  Session requests: {status.requests_made}", Colors.DIM)

        if self.current_tests:
            self._print(f"  Tests generated: {len(self.current_tests)}", Colors.DIM)

    async def _show_tests(self):
        """Show current tests."""
        if not self.current_tests:
            self._print_agent("No tests generated yet. Tell me what to test!")
            return

        response = format_test_cases(self.current_tests, OutputStyle.STANDARD)
        self._print_agent(str(response))

        # Offer to show details
        self._print(f"\n{Colors.DIM}Type 'details' for full test cases{Colors.RESET}")

    async def _export_tests(self, filename: str):
        """Export tests to file."""
        if not self.current_tests:
            self._print_agent("No tests to export. Generate some first!")
            return

        import json
        with open(filename, "w") as f:
            json.dump(self.current_tests, f, indent=2)

        self._print_success(f"Exported {len(self.current_tests)} tests to {filename}")

    def _show_sessions(self):
        """Show saved sessions."""
        sessions = self.session_store.list_sessions()
        if not sessions:
            self._print_agent("No saved sessions yet.")
            return

        self._print_agent("Saved sessions:")
        for s in sessions:
            feature = s.feature_focus or "Unknown feature"
            self._print(f"  • {s.session_id}: {feature} ({s.test_count} tests)", Colors.DIM)

    async def _process_input(self, text: str) -> bool:
        """
        Process user input.

        Returns:
            True if should continue, False to exit
        """
        # Check for command
        cmd, args = self._parse_command(text)
        if cmd:
            return await self._handle_command(cmd, args)

        # Natural language processing
        await self._ensure_initialized()

        # Store in conversation
        self.conversation.receive(text)

        # Understand intent
        text_lower = text.lower()

        # Test generation intent
        if any(word in text_lower for word in ["test", "testing", "tests", "generate", "create"]):
            await self._generate_tests(text)

        # Analysis intent
        elif any(word in text_lower for word in ["analyze", "check", "look at", "review"]):
            await self._analyze_page(text)

        # Security intent
        elif any(word in text_lower for word in ["security", "secure", "vulnerability", "xss", "injection"]):
            await self._security_analysis(text)

        # Question/clarification
        elif "?" in text:
            await self._answer_question(text)

        # Default: try to understand
        else:
            await self._understand_request(text)

        return True

    async def _generate_tests(self, request: str):
        """Generate tests based on request."""
        # Detect feature/page type
        feature = self.conversation.current_feature or "the feature"
        page_type = self.conversation.current_page_type

        self._print_thinking(f"Understanding what to test...")

        # If we don't have enough context, ask
        if not page_type:
            self._print_agent(f"I want to make sure I test the right things.")
            self._print(f"\n{Colors.DIM}What type of page/feature is this?{Colors.RESET}")
            self._print(f"{Colors.DIM}  (login / signup / checkout / search / form / other){Colors.RESET}")
            return

        # Generate
        self._print_agent(acknowledge_task(feature))

        self._print_thinking("Searching knowledge base for relevant rules...")
        time.sleep(0.3)  # Small delay for natural feel

        self._print_thinking("Generating comprehensive test cases...")

        try:
            result = await self.agent.generate_tests(
                feature=feature,
                page_type=page_type,
            )

            # Store tests
            self.current_tests = [t.to_dict() for t in result.suite.tests]

            # Format response
            response = format_test_cases(self.current_tests, OutputStyle.STANDARD)

            self._print_agent(str(response))

            # Show follow-up
            if result.suggestions:
                self._print(f"\n{Colors.DIM}Suggestions:{Colors.RESET}")
                for s in result.suggestions[:2]:
                    self._print(f"  → {s}", Colors.DIM)

        except Exception as e:
            self._print_error(f"Couldn't generate tests: {e}")
            self._print_agent("Let me try with different parameters. Can you give me more details?")

    async def _analyze_page(self, request: str):
        """Analyze a page."""
        self._print_agent("I'd need to see the page to analyze it.")
        self._print(f"\n{Colors.DIM}You can:{Colors.RESET}")
        self._print(f"  1. Give me a URL to analyze", Colors.DIM)
        self._print(f"  2. Describe the page elements", Colors.DIM)
        self._print(f"  3. Paste the element list from your browser", Colors.DIM)

    async def _security_analysis(self, request: str):
        """Security-focused analysis."""
        self._print_agent("Security testing is important. Let me help.")

        page_type = self.conversation.current_page_type or "form"

        self._print_thinking(f"Retrieving security rules for {page_type} pages...")

        # Generate security-focused tests
        try:
            result = await self.agent.generate_tests(
                feature=f"Security testing for {page_type}",
                page_type=page_type,
                context="Focus on security vulnerabilities: XSS, CSRF, injection, auth bypass",
            )

            security_tests = [
                t.to_dict() for t in result.suite.tests
                if t.category.value in ["security", "negative", "edge_case"]
            ]

            self.current_tests = security_tests

            if security_tests:
                self._print_agent(f"Generated {len(security_tests)} security-focused tests.")
                response = format_test_cases(security_tests, OutputStyle.STANDARD, max_show=5)
                print(str(response))
            else:
                self._print_warning("Couldn't find specific security tests. Here are general tests instead.")
                self.current_tests = [t.to_dict() for t in result.suite.tests]
                response = format_test_cases(self.current_tests, OutputStyle.STANDARD)
                print(str(response))

        except Exception as e:
            self._print_error(f"Security analysis failed: {e}")

    async def _answer_question(self, question: str):
        """Answer a question."""
        self._print_thinking("Let me think about that...")

        # Simple Q&A based on keywords
        question_lower = question.lower()

        if "how many" in question_lower and "test" in question_lower:
            self._print_agent(f"I've generated {len(self.current_tests)} tests so far.")

        elif "what" in question_lower and "next" in question_lower:
            self._print_agent("Good question! I'd suggest:")
            self._print(f"  1. Review the generated tests", Colors.DIM)
            self._print(f"  2. Tell me if any scenarios are missing", Colors.DIM)
            self._print(f"  3. Export and run the tests", Colors.DIM)

        else:
            self._print_agent("I'm not sure I understand. Could you rephrase that?")

    async def _understand_request(self, text: str):
        """Try to understand an ambiguous request."""
        self._print_agent("I want to make sure I understand correctly.")
        self._print(f"\n{Colors.DIM}Are you looking to:{Colors.RESET}")
        self._print(f"  1. Generate test cases", Colors.DIM)
        self._print(f"  2. Analyze a page", Colors.DIM)
        self._print(f"  3. Check security", Colors.DIM)
        self._print(f"  4. Something else?", Colors.DIM)

    def _try_resume_session(self) -> bool:
        """Try to resume a previous session."""
        summary = get_session_summary()
        if summary:
            self._print(f"\n{Colors.DIM}📝 Previous session: {summary}{Colors.RESET}")
            self._print(f"{Colors.DIM}   Type 'continue' to resume or just start fresh{Colors.RESET}")
            return True
        return False

    def _load_previous_session(self):
        """Load the most recent session into memory."""
        latest_id = self.session_store.get_latest_session()
        if latest_id:
            loaded = self.session_store.load_session(latest_id)
            if loaded:
                self.memory = loaded
                self._session_resumed = True
                self._print_success("Resumed previous session")
                if self.memory.working.current_feature:
                    self._print(f"  {Colors.DIM}Feature: {self.memory.working.current_feature}{Colors.RESET}")
                return True
        return False

    def _save_session(self):
        """Save current session on exit."""
        if self.memory.conversation_history:
            session_id = self.session_store.save_session(self.memory)
            self._print(f"\n{Colors.DIM}💾 Session saved (ID: {session_id[:20]}...){Colors.RESET}")

    async def run(self):
        """Run the interactive CLI."""
        self._print_header()

        # Check for previous session
        has_previous = self._try_resume_session()

        # Greeting
        self._print_agent(greet())

        # Main loop
        running = True
        while running:
            try:
                text = self._print_prompt()
                if not text:
                    continue

                # Handle session resume
                if text.lower() == "continue" and not self._session_resumed:
                    if self._load_previous_session():
                        continue

                running = await self._process_input(text)

            except KeyboardInterrupt:
                self._print("\n")
                self._print_agent("Interrupted. Type /quit to exit.")

            except Exception as e:
                self._print_error(f"Something went wrong: {e}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()

        # Save session on exit
        self._save_session()


async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="TestAI Agent - Your QA colleague")
    parser.add_argument("--analyze", "-a", help="Analyze a URL")
    parser.add_argument("--test", "-t", help="Generate tests for a feature")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    interface = QAInterface()
    interface.verbose = args.verbose

    if args.analyze or args.test:
        # Non-interactive mode
        await interface._ensure_initialized()

        if args.analyze:
            await interface._analyze_page(args.analyze)
        elif args.test:
            interface.conversation.current_feature = args.test
            # Try to detect page type from feature name
            for pt in ["login", "signup", "checkout", "search"]:
                if pt in args.test.lower():
                    interface.conversation.current_page_type = pt
                    break
            else:
                interface.conversation.current_page_type = "form"

            await interface._generate_tests(args.test)
    else:
        # Interactive mode
        await interface.run()


if __name__ == "__main__":
    asyncio.run(main())
