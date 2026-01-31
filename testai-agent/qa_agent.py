#!/usr/bin/env python3
"""
TestAI QA Agent - Human-Like QA Expert

A REAL AI-powered QA agent that:
1. Has a Brain with comprehensive testing knowledge
2. Responds like a senior human QA engineer
3. Generates test cases using AI + Brain knowledge
4. Is designed for future skills (Playwright, test scripts, etc.)

Usage:
    python qa_agent.py

    > hi
    Hey there! I'm your QA partner. What are we testing today?

    > test the login page
    [Generates comprehensive tests using Brain + AI]
"""

import asyncio
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

# Import gateway
from gateway.base import Message
from gateway.deepseek import DeepSeekProvider, ProviderConfig


# ─────────────────────────────────────────────────────────────────
# QA BRAIN - Built-in Testing Knowledge
# ─────────────────────────────────────────────────────────────────

class QAKnowledge:
    """
    The QA Brain - contains comprehensive testing patterns.
    This is built-in knowledge that the AI uses to generate tests.
    """

    # Testing patterns by category
    PATTERNS = {
        "login": {
            "functional": [
                "Valid credentials lead to successful login",
                "Invalid email shows appropriate error message",
                "Invalid password shows appropriate error message",
                "Empty email field prevents submission",
                "Empty password field prevents submission",
                "Remember me checkbox persists session",
                "Forgot password link is accessible",
            ],
            "security": [
                "SQL injection in email field (test: ' OR '1'='1)",
                "SQL injection in password field",
                "XSS attempt in email field (test: <script>alert(1)</script>)",
                "Brute force protection (account lockout after N attempts)",
                "Password not visible in page source",
                "HTTPS enforced for login",
                "Session token regenerated after login",
                "CSRF token validation",
            ],
            "edge_cases": [
                "Very long email (255+ characters)",
                "Email with special characters (user+tag@domain.com)",
                "Unicode characters in password",
                "Leading/trailing spaces in credentials",
                "Case sensitivity handling (Email vs email)",
                "Multiple tabs/sessions behavior",
            ],
            "ui_ux": [
                "Password visibility toggle works",
                "Form is keyboard accessible (Tab navigation)",
                "Error messages are clear and helpful",
                "Loading state during submission",
                "Mobile responsive layout",
            ],
        },
        "signup": {
            "functional": [
                "Valid registration creates new account",
                "Duplicate email shows error",
                "Password confirmation matches",
                "All required fields validated",
                "Email verification sent",
            ],
            "security": [
                "Password strength requirements enforced",
                "Rate limiting on registration",
                "CAPTCHA prevents automation",
                "Email confirmation required before access",
            ],
        },
        "checkout": {
            "functional": [
                "Cart total calculates correctly",
                "Shipping options display properly",
                "Payment processing works",
                "Order confirmation received",
                "Inventory updated after purchase",
            ],
            "security": [
                "Payment data encrypted (PCI compliance)",
                "Price tampering prevented",
                "Session hijacking protection",
            ],
        },
        "search": {
            "functional": [
                "Relevant results returned",
                "Empty search handled gracefully",
                "Pagination works correctly",
                "Filters apply properly",
            ],
            "security": [
                "SQL injection in search field",
                "XSS in search results",
            ],
        },
    }

    # Human-like responses
    RESPONSES = {
        "greeting": [
            "Hey there! I'm your QA partner. What are we testing today?",
            "Hi! Ready to find some bugs. What's on the testing agenda?",
            "Hello! Let's make sure everything works perfectly. What feature?",
        ],
        "thinking": [
            "Let me think through the test scenarios...",
            "Analyzing the potential edge cases...",
            "Consulting my testing knowledge base...",
            "Thinking like a user who might break this...",
        ],
        "clarify": [
            "Before I generate tests, can you tell me more about {}?",
            "I want to make sure I cover everything. What's the {} behavior?",
            "Quick question: Does {} have any specific requirements?",
        ],
    }

    @classmethod
    def get_patterns(cls, feature_type: str, category: str = None) -> List[str]:
        """Get testing patterns for a feature type."""
        patterns = cls.PATTERNS.get(feature_type.lower(), {})
        if category:
            return patterns.get(category, [])
        # Return all patterns
        all_patterns = []
        for cat_patterns in patterns.values():
            all_patterns.extend(cat_patterns)
        return all_patterns

    @classmethod
    def detect_feature_type(cls, text: str) -> str:
        """Detect what type of feature is being discussed."""
        text_lower = text.lower()
        if any(w in text_lower for w in ["login", "sign in", "signin", "auth"]):
            return "login"
        if any(w in text_lower for w in ["signup", "register", "sign up", "create account"]):
            return "signup"
        if any(w in text_lower for w in ["checkout", "payment", "cart", "purchase"]):
            return "checkout"
        if any(w in text_lower for w in ["search", "find", "query"]):
            return "search"
        return "general"


# ─────────────────────────────────────────────────────────────────
# DEEPSEEK PROVIDER
# ─────────────────────────────────────────────────────────────────

class QAAgent:
    """
    Human-like QA Agent powered by DeepSeek + Built-in Knowledge.

    Features:
    - Responds naturally like a senior QA engineer
    - Uses Brain knowledge to generate comprehensive tests
    - Tracks conversation context
    - Designed for future skill extensions
    """

    # System prompt that makes the AI behave like a human QA
    SYSTEM_PROMPT = """You are a senior QA engineer with 10+ years of experience.

Your personality:
- Professional but friendly
- Thorough and detail-oriented
- Thinks about edge cases and security
- Explains your reasoning
- Asks clarifying questions when needed

When generating test cases:
1. Use the KNOWLEDGE BASE provided to ensure comprehensive coverage
2. Include test ID, title, steps, expected results
3. Cover functional, security, edge cases, and UI/UX
4. Prioritize tests by criticality
5. Cite which category each test comes from

Format test cases as:
### TC-XXX: [Title]
- **Priority:** Critical/High/Medium/Low
- **Category:** Functional/Security/Edge Case/UI-UX
- **Steps:**
  1. Step one
  2. Step two
- **Expected:** What should happen
- **Why:** Why this test matters

Be concise but thorough. Think like someone who wants to break the application.
"""

    def __init__(self, api_key: str = None):
        """Initialize the QA Agent."""
        self.api_key = api_key or "sk-c104455631bb433b801fc4a16042419c"
        self.provider = None
        self.messages: List[Message] = []
        self.call_count = 0
        self.max_calls = 50

        # Initialize provider
        self._init_provider()

    def _init_provider(self):
        """Initialize the DeepSeek provider."""
        config = ProviderConfig(
            api_key=self.api_key,
            default_model="deepseek-chat",
        )
        self.provider = DeepSeekProvider(config)

    async def chat(self, user_input: str) -> str:
        """
        Chat with the QA Agent.

        This combines Brain knowledge with AI generation.
        """
        # Check call limit
        if self.call_count >= self.max_calls:
            return f"⚠️ API limit reached ({self.call_count}/{self.max_calls} calls). Please wait."

        # Detect feature type
        feature_type = QAKnowledge.detect_feature_type(user_input)

        # Get relevant knowledge
        patterns = QAKnowledge.get_patterns(feature_type)
        knowledge_context = ""
        if patterns:
            knowledge_context = f"""
KNOWLEDGE BASE for {feature_type.upper()}:
{chr(10).join(f'- {p}' for p in patterns)}

Use these patterns to ensure comprehensive test coverage.
"""

        # Build system prompt with knowledge
        system = self.SYSTEM_PROMPT + knowledge_context

        # Add user message
        self.messages.append(Message(role="user", content=user_input))

        try:
            # Call DeepSeek
            response = await self.provider.complete(
                prompt=user_input,
                system=system,
                temperature=0.7,
                max_tokens=4096,
            )

            self.call_count += 1

            # Add to history
            self.messages.append(Message(role="assistant", content=response.content))

            return response.content

        except Exception as e:
            return f"❌ Error: {str(e)}"

    async def generate_tests(self, feature: str, url: str = None) -> str:
        """Generate comprehensive test cases for a feature."""
        feature_type = QAKnowledge.detect_feature_type(feature)
        patterns = QAKnowledge.get_patterns(feature_type)

        prompt = f"""Generate comprehensive test cases for: {feature}
{f"URL: {url}" if url else ""}

Use the knowledge base patterns to ensure coverage.
Generate at least 10 test cases covering:
- Functional tests (happy path)
- Security tests (injections, auth bypass)
- Edge cases (boundary conditions)
- UI/UX tests (accessibility, mobile)

For each test, explain WHY it matters.
"""
        return await self.chat(prompt)

    def get_status(self) -> str:
        """Get agent status."""
        return f"""
📊 QA Agent Status
────────────────────────
API Calls: {self.call_count}/{self.max_calls}
Messages: {len(self.messages)}
Ready: {'✅ Yes' if self.call_count < self.max_calls else '❌ Limit reached'}
"""

    def clear_history(self):
        """Clear conversation history."""
        self.messages = []


# ─────────────────────────────────────────────────────────────────
# INTERACTIVE CLI
# ─────────────────────────────────────────────────────────────────

class Colors:
    """Terminal colors."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[38;5;108m"
    YELLOW = "\033[38;5;179m"
    RED = "\033[38;5;167m"
    CYAN = "\033[38;5;73m"
    GRAY = "\033[38;5;245m"
    BLUE = "\033[38;5;67m"


def print_header():
    """Print welcome header."""
    print()
    print(f"{Colors.BLUE}╔══════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.BLUE}║{Colors.RESET}                                                          {Colors.BLUE}║{Colors.RESET}")
    print(f"{Colors.BLUE}║{Colors.RESET}   {Colors.BOLD}🧪 TestAI QA Agent{Colors.RESET}                                    {Colors.BLUE}║{Colors.RESET}")
    print(f"{Colors.BLUE}║{Colors.RESET}   {Colors.DIM}Your AI QA Partner - Thinks Like a Human{Colors.RESET}              {Colors.BLUE}║{Colors.RESET}")
    print(f"{Colors.BLUE}║{Colors.RESET}                                                          {Colors.BLUE}║{Colors.RESET}")
    print(f"{Colors.BLUE}╚══════════════════════════════════════════════════════════╝{Colors.RESET}")
    print()
    print(f"{Colors.GRAY}Commands:{Colors.RESET}")
    print(f"{Colors.DIM}  /test <feature>  Generate comprehensive tests{Colors.RESET}")
    print(f"{Colors.DIM}  /status          Show agent status{Colors.RESET}")
    print(f"{Colors.DIM}  /clear           Clear conversation{Colors.RESET}")
    print(f"{Colors.DIM}  /quit            Exit{Colors.RESET}")
    print(f"{Colors.DIM}  Or just chat naturally!{Colors.RESET}")
    print()


async def interactive_mode():
    """Run the interactive CLI."""
    print_header()

    agent = QAAgent()
    print(f"{Colors.GREEN}✓ Agent ready!{Colors.RESET}")
    print(agent.get_status())

    running = True
    while running:
        try:
            print(f"{Colors.CYAN}You:{Colors.RESET} ", end="")
            user_input = input().strip()

            if not user_input:
                continue

            # Handle commands
            if user_input.startswith("/"):
                parts = user_input[1:].split(maxsplit=1)
                cmd = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""

                if cmd in ["quit", "exit", "q"]:
                    print(f"\n{Colors.CYAN}👋 Happy testing! See you next time.{Colors.RESET}")
                    running = False

                elif cmd == "test":
                    if args:
                        print(f"\n{Colors.DIM}💭 Generating comprehensive tests...{Colors.RESET}\n")
                        response = await agent.generate_tests(args)
                        print(f"{Colors.GREEN}Agent:{Colors.RESET}\n{response}\n")
                    else:
                        print(f"{Colors.YELLOW}Usage: /test <feature>{Colors.RESET}")

                elif cmd == "status":
                    print(agent.get_status())

                elif cmd == "clear":
                    agent.clear_history()
                    print(f"{Colors.GREEN}✓ Conversation cleared{Colors.RESET}")

                elif cmd == "help":
                    print_header()

                else:
                    print(f"{Colors.YELLOW}Unknown command: /{cmd}{Colors.RESET}")

            # Natural chat
            else:
                print(f"\n{Colors.DIM}💭 Thinking...{Colors.RESET}\n")
                response = await agent.chat(user_input)
                print(f"{Colors.GREEN}Agent:{Colors.RESET}\n{response}\n")

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Use /quit to exit{Colors.RESET}")

        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.RESET}")

    return agent


async def main():
    """Main entry point."""
    # Check for command line arguments
    if len(sys.argv) > 1:
        prompt = " ".join(sys.argv[1:])
        agent = QAAgent()
        print(f"{Colors.DIM}💭 Processing: {prompt}{Colors.RESET}\n")
        response = await agent.chat(prompt)
        print(response)
        return

    # Interactive mode
    await interactive_mode()


if __name__ == "__main__":
    asyncio.run(main())
