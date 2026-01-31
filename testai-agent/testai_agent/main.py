#!/usr/bin/env python3
"""
TestAI Agent - Main Entry Point

A cognitive QA system that:
1. Ingests feature specifications
2. Retrieves exact testing rules from the Brain (RAG)
3. Generates exhaustive test cases with citations
4. Behaves like a Senior European QA Consultant

Usage:
    python -m testai_agent.main

Or as a CLI:
    python testai_agent/main.py
"""

import asyncio
import sys
import os
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from testai_agent.brain.vector_store import QABrain, create_brain
from testai_agent.connectors.llm_gateway import (
    LLMGateway, LLMProvider, DeepSeekConnector, create_gateway
)
from testai_agent.core.cortex import Cortex, create_cortex
from testai_agent.interface.cli import ConsoleUI, create_thinking_callback


# Default DeepSeek API key
DEFAULT_DEEPSEEK_KEY = "sk-c104455631bb433b801fc4a16042419c"

# Default knowledge base path
DEFAULT_BRAIN_PATH = Path(__file__).parent.parent / "QA_BRAIN.md"


class TestAIAgent:
    """
    The main TestAI Agent orchestrator.

    Coordinates between:
    - Brain (knowledge storage and retrieval)
    - Gateway (LLM API access)
    - Cortex (reasoning engine)
    - UI (user interface)
    """

    def __init__(
        self,
        deepseek_key: str = None,
        brain_path: str = None,
        max_calls: int = 10
    ):
        self.ui = ConsoleUI()

        # Initialize Brain
        self.ui.animate_progress("Initializing Brain (RAG system)...")
        self.brain = create_brain()

        # Check if brain needs loading
        if not self.brain.is_ready:
            brain_file = brain_path or DEFAULT_BRAIN_PATH
            if Path(brain_file).exists():
                self.ui.animate_progress(f"Loading knowledge from {brain_file}...")
                result = self.brain.ingest(str(brain_file))
                if result.get("status") == "success":
                    self.ui.print_success(f"Loaded {result.get('chunks', 0)} knowledge chunks")
                else:
                    self.ui.print_warning(f"Brain loading: {result.get('message', 'Unknown')}")
            else:
                self.ui.print_warning(f"Knowledge base not found at {brain_file}")

        # Initialize Gateway
        self.ui.animate_progress("Initializing LLM Gateway...")
        api_key = deepseek_key or os.getenv("DEEPSEEK_API_KEY") or DEFAULT_DEEPSEEK_KEY

        self.gateway = LLMGateway()
        self.gateway.add_provider(DeepSeekConnector(
            api_key=api_key,
            model="deepseek-chat",
            max_calls=max_calls
        ))

        # Initialize Cortex
        self.ui.animate_progress("Initializing Cortex (reasoning engine)...")
        thinking_callback = create_thinking_callback(self.ui)
        self.cortex = create_cortex(self.brain, self.gateway, thinking_callback)

        self.ui.print_success("All systems initialized")

    def show_status(self):
        """Show system status."""
        brain_status = self.brain.get_status()
        gateway_status = self.gateway.get_usage_status()
        self.ui.print_status(brain_status, gateway_status)

    async def generate_test_plan(self, feature: str):
        """Generate a test plan for a feature."""
        self.ui.print_info(f"Generating test plan for: {feature}")
        self.ui.print_divider()

        # Check for clarification needed
        questions = await self.cortex.check_for_clarification(feature)

        if questions:
            for q in questions:
                self.ui.print_question(
                    q.question,
                    q.options,
                    q.context
                )
                choice = self.ui.prompt_choice("Your choice (or press Enter to skip)")
                # For now, we continue regardless of choice
                # In a full implementation, this would modify the generation

        # Generate test plan
        try:
            test_plan = await self.cortex.generate_test_plan(feature)
            self.ui.end_thinking()
            self.ui.print_test_plan(test_plan)

            # Show final status
            self.ui.print_divider()
            self.ui.print_success(f"Generated {test_plan.total_tests} test cases")
            self.show_status()

            return test_plan

        except Exception as e:
            self.ui.end_thinking()
            self.ui.print_error(f"Failed to generate test plan: {str(e)}")
            return None

    async def analyze_feature(self, feature: str):
        """Analyze a feature without generating full test plan."""
        self.ui.print_info(f"Analyzing: {feature}")
        self.ui.print_divider()

        analysis = await self.cortex.analyze_feature(feature)

        print(f"\n  Feature Type: {analysis['page_type']}")
        print(f"  Complexity: {analysis['complexity']}")
        print(f"  Has Payment: {analysis['has_payment']}")
        print(f"  Has Auth: {analysis['has_auth']}")
        print(f"  Sensitive Data: {analysis['has_sensitive_data']}")

        # Get relevant knowledge
        result = self.brain.retrieve_for_feature(feature)
        print(f"\n  Relevant Knowledge: {result.total_found} items")
        print(f"  Confidence: {result.confidence:.0%}")

        print("\n  Knowledge Sources:")
        for k in result.knowledge[:5]:
            print(f"    • {k.citation}")

        self.ui.print_divider()

    async def interactive_loop(self):
        """Run the interactive CLI loop."""
        self.ui.print_header()
        self.show_status()

        print("\nHow can I help you today? (type 'help' for commands)")

        while True:
            try:
                user_input = input("\n🧪 > ").strip()

                if not user_input:
                    continue

                # Parse command
                parts = user_input.split(maxsplit=1)
                command = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""

                if command in ["exit", "quit", "q"]:
                    self.ui.print_info("Goodbye! Happy testing!")
                    break

                elif command == "help":
                    self.ui.print_help()

                elif command == "status":
                    self.show_status()

                elif command == "test":
                    if not args:
                        self.ui.print_warning("Please specify a feature to test. Example: test login page")
                    else:
                        await self.generate_test_plan(args)

                elif command == "analyze":
                    if not args:
                        self.ui.print_warning("Please specify a feature to analyze. Example: analyze checkout flow")
                    else:
                        await self.analyze_feature(args)

                else:
                    # Treat the entire input as a feature to test
                    await self.generate_test_plan(user_input)

            except KeyboardInterrupt:
                print("\n")
                self.ui.print_warning("Use 'exit' to quit")

            except Exception as e:
                self.ui.print_error(f"Error: {str(e)}")


async def main():
    """Main entry point."""
    # Check for command line arguments
    if len(sys.argv) > 1:
        feature = " ".join(sys.argv[1:])
        agent = TestAIAgent()
        await agent.generate_test_plan(feature)
    else:
        # Interactive mode
        agent = TestAIAgent()
        await agent.interactive_loop()


if __name__ == "__main__":
    asyncio.run(main())
