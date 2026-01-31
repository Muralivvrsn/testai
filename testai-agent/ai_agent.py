#!/usr/bin/env python3
"""
TestAI Agent - REAL AI-Powered QA Agent

This is the ACTUAL AI agent that uses DeepSeek for:
1. Understanding user requests
2. Generating test cases
3. Natural conversation
4. Everything is AI-powered, not templates!

Usage:
    python ai_agent.py

    > hi
    Hey! I'm your AI QA colleague. What would you like me to test?

    > test the login page on example.com
    [AI generates comprehensive tests using DeepSeek]

    > generate a report
    [AI creates a detailed report]
"""

import asyncio
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

# Import the LLM gateway
from connectors.llm_gateway import LLMGateway, create_gateway, ProviderName
from gateway.base import Message

# Import Playwright runner for real testing
try:
    from runner.playwright_runner import PlaywrightRunner, TestCase, TestStatus
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class Colors:
    """Terminal colors."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    BLUE = "\033[38;5;67m"
    GREEN = "\033[38;5;108m"
    YELLOW = "\033[38;5;179m"
    RED = "\033[38;5;167m"
    CYAN = "\033[38;5;73m"
    GRAY = "\033[38;5;245m"


# QA Expert System Prompt
SYSTEM_PROMPT = """You are TestAI, an elite QA specialist and testing expert.

Your capabilities:
1. Generate comprehensive test cases for any feature
2. Analyze websites and suggest testing strategies
3. Create test reports and risk assessments
4. Help users understand testing best practices

When users ask you to test something:
- Generate detailed, actionable test cases
- Include test ID, title, steps, expected results
- Cover security, functional, UI, edge cases
- Cite your reasoning

When users just chat:
- Be friendly, professional, and helpful
- Ask clarifying questions when needed
- Keep responses concise but informative

Response format for test cases:
```
## Test Cases for [Feature]

### TC-001: [Title]
**Priority:** High/Medium/Low
**Category:** Security/Functional/UI/Edge Case
**Steps:**
1. Step one
2. Step two
3. Step three
**Expected Result:** What should happen
**Rationale:** Why this test matters
```

When generating tests, ALWAYS:
- Cover both happy path and edge cases
- Include security tests (XSS, SQL injection, auth bypass)
- Test validation and error handling
- Consider accessibility and performance
- Be specific about selectors and actions

Keep your responses focused and actionable. You are a senior QA consultant who knows their craft.
"""


class AIAgent:
    """
    Real AI-powered QA Agent.

    Uses DeepSeek API for all responses - no templates!
    """

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the AI agent."""
        # Use provided key or default
        self.api_key = api_key or "sk-c104455631bb433b801fc4a16042419c"

        # Create gateway
        self.gateway = create_gateway(
            deepseek_key=self.api_key,
            max_calls=50,  # Allow more calls for real usage
        )

        # Conversation history
        self.messages: List[Message] = []

        # Playwright runner for real tests
        self.runner: Optional[PlaywrightRunner] = None

        # Test history
        self.test_results: List[Dict] = []

    async def start(self):
        """Start the agent."""
        if PLAYWRIGHT_AVAILABLE:
            self.runner = PlaywrightRunner(headless=True)
            await self.runner.start()

    async def stop(self):
        """Stop the agent."""
        if self.runner:
            await self.runner.stop()

    async def chat(self, user_input: str) -> str:
        """
        Chat with the AI agent.

        This calls the REAL DeepSeek API for responses.
        """
        # Check if we can call
        if not self.gateway.can_call():
            remaining = self.gateway.usage_tracker.get_remaining(ProviderName.DEEPSEEK)
            return f"❌ API limit reached ({remaining['calls_used']} calls used). Please wait or configure more calls."

        # Add user message to history
        self.messages.append(Message(role="user", content=user_input))

        # Call the AI
        response = await self.gateway.chat(
            messages=self.messages,
            temperature=0.7,
            max_tokens=4096,
        )

        # Check for errors
        if response.finish_reason == "error":
            return f"❌ Error: {response.content}"

        # Add assistant response to history
        self.messages.append(Message(role="assistant", content=response.content))

        return response.content

    async def generate_tests(self, feature: str, url: Optional[str] = None) -> str:
        """
        Generate test cases for a feature using AI.

        Args:
            feature: What to test (e.g., "login page")
            url: Optional URL to test

        Returns:
            AI-generated test cases
        """
        prompt = f"""Generate comprehensive test cases for: {feature}

{"URL to test: " + url if url else ""}

Include:
1. At least 5-10 test cases
2. Security tests (XSS, SQL injection, CSRF)
3. Functional tests (happy path, validation)
4. Edge cases (empty fields, special chars)
5. UI/UX tests (layout, responsiveness)

For each test, provide:
- Test ID (TC-001, TC-002, etc.)
- Title
- Priority (Critical/High/Medium/Low)
- Category
- Detailed steps
- Expected result
- Why this test matters

Be specific and actionable. This is for a professional QA team."""

        return await self.chat(prompt)

    async def run_test(self, url: str, steps: List[Dict]) -> Dict:
        """
        Actually run a test using Playwright.

        Args:
            url: URL to test
            steps: Test steps to execute

        Returns:
            Test result
        """
        if not PLAYWRIGHT_AVAILABLE or not self.runner:
            return {
                "status": "skipped",
                "error": "Playwright not available. Install with: pip install playwright && playwright install"
            }

        test = TestCase(
            name=f"Test on {url}",
            url=url,
            steps=steps,
        )

        result = await self.runner.run_test(test)

        return {
            "status": result.status.value,
            "duration_ms": result.duration_ms,
            "steps_passed": len([s for s in result.steps if s.status == TestStatus.PASSED]),
            "steps_failed": len([s for s in result.steps if s.status == TestStatus.FAILED]),
            "error": result.error,
            "screenshot": result.screenshot_path,
        }

    async def generate_report(self) -> str:
        """Generate a report of all tests run."""
        if not self.test_results:
            return "No tests have been run yet. Ask me to test something first!"

        prompt = f"""Generate a professional QA test report based on these results:

{self.test_results}

Include:
1. Executive Summary
2. Test Statistics (pass/fail rates)
3. Key Findings
4. Risk Assessment
5. Recommendations

Format as a professional report suitable for stakeholders."""

        return await self.chat(prompt)

    def get_usage(self) -> str:
        """Get API usage status."""
        return self.gateway.format_usage_status()

    def clear_history(self):
        """Clear conversation history."""
        self.messages = []


class AgentCLI:
    """Interactive CLI for the AI Agent."""

    def __init__(self):
        self.agent = AIAgent()

    def print(self, text: str = "", color: str = "", end: str = "\n"):
        """Print with color."""
        print(f"{color}{text}{Colors.RESET}", end=end)

    def print_header(self):
        """Print welcome header."""
        print()
        self.print("╔════════════════════════════════════════════════════════╗", Colors.BLUE)
        self.print("║                                                        ║", Colors.BLUE)
        self.print("║   🤖 TestAI Agent - AI-Powered QA                      ║", Colors.BLUE + Colors.BOLD)
        self.print("║   Powered by DeepSeek API                              ║", Colors.BLUE)
        self.print("║                                                        ║", Colors.BLUE)
        self.print("╚════════════════════════════════════════════════════════╝", Colors.BLUE)
        print()
        self.print("Commands:", Colors.GRAY)
        self.print("  /test <feature>  - Generate tests", Colors.DIM)
        self.print("  /run <url>       - Run tests on URL", Colors.DIM)
        self.print("  /report          - Generate report", Colors.DIM)
        self.print("  /usage           - Check API usage", Colors.DIM)
        self.print("  /clear           - Clear history", Colors.DIM)
        self.print("  /quit            - Exit", Colors.DIM)
        self.print("\nOr just chat naturally!", Colors.DIM)
        print()

    async def run(self):
        """Run the interactive CLI."""
        self.print_header()

        # Start the agent
        self.print("Starting agent...", Colors.DIM)
        await self.agent.start()
        self.print("✓ Agent ready!", Colors.GREEN)
        print()

        # Show API status
        self.print(self.agent.get_usage(), Colors.GRAY)
        print()

        running = True
        while running:
            try:
                # Get input
                self.print("You: ", Colors.CYAN, end="")
                user_input = input().strip()

                if not user_input:
                    continue

                # Handle commands
                if user_input.startswith("/"):
                    parts = user_input[1:].split(maxsplit=1)
                    cmd = parts[0].lower()
                    args = parts[1] if len(parts) > 1 else ""

                    if cmd in ["quit", "exit", "q"]:
                        running = False
                        self.print("\n👋 Goodbye!", Colors.CYAN)
                        continue

                    elif cmd == "test":
                        if args:
                            self.print("\n💭 Generating tests...", Colors.DIM)
                            response = await self.agent.generate_tests(args)
                            self.print(f"\n{Colors.GREEN}AI:{Colors.RESET} {response}")
                        else:
                            self.print("Usage: /test <feature>", Colors.YELLOW)

                    elif cmd == "run":
                        if args:
                            self.print(f"\n🌐 Running tests on {args}...", Colors.DIM)
                            # First generate, then run
                            steps = [
                                {"action": "assert_visible", "selector": "body"},
                                {"action": "screenshot", "value": "test.png"},
                            ]
                            result = await self.agent.run_test(args, steps)
                            self.print(f"\nResult: {result}", Colors.GREEN)
                        else:
                            self.print("Usage: /run <url>", Colors.YELLOW)

                    elif cmd == "report":
                        self.print("\n📊 Generating report...", Colors.DIM)
                        response = await self.agent.generate_report()
                        self.print(f"\n{response}")

                    elif cmd == "usage":
                        self.print(f"\n{self.agent.get_usage()}")

                    elif cmd == "clear":
                        self.agent.clear_history()
                        self.print("✓ History cleared", Colors.GREEN)

                    elif cmd == "help":
                        self.print_header()

                    else:
                        self.print(f"Unknown command: /{cmd}", Colors.YELLOW)

                # Natural language chat
                else:
                    self.print("\n💭 Thinking...", Colors.DIM)
                    response = await self.agent.chat(user_input)
                    self.print(f"\n{Colors.GREEN}AI:{Colors.RESET} {response}")
                    print()

            except KeyboardInterrupt:
                print()
                self.print("Use /quit to exit", Colors.YELLOW)

            except Exception as e:
                self.print(f"\n❌ Error: {e}", Colors.RED)

        # Cleanup
        await self.agent.stop()


async def main():
    """Main entry point."""
    # Check for quick mode
    if len(sys.argv) > 1:
        prompt = " ".join(sys.argv[1:])
        agent = AIAgent()

        print(f"{Colors.DIM}💭 Processing: {prompt}{Colors.RESET}")
        response = await agent.chat(prompt)
        print(f"\n{response}")
        return

    # Interactive mode
    cli = AgentCLI()
    await cli.run()


if __name__ == "__main__":
    asyncio.run(main())
