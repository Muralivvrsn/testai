#!/usr/bin/env python3
"""
TestAI Agent - Main Entry Point

The intelligent QA agent that thinks like a human, tests like a machine.
Now with citation-aware reasoning for zero-hallucination.

Usage:
    # Interactive demo (no API needed)
    python main.py demo

    # Interactive CLI with thinking display
    python main.py cli

    # Generate tests with visible reasoning
    python main.py generate "login page"

    # Generate tests using templates only (no API)
    python main.py generate "login page" --offline

    # Security-focused analysis
    python main.py security "checkout page"

    # Show system status
    python main.py status

    # Show API usage
    python main.py usage

Environment:
    DEEPSEEK_API_KEY: Your DeepSeek API key (defaults to test key with 10 call limit)
"""

import sys
import os
import argparse
import asyncio
import time
from pathlib import Path
from typing import Optional

# Ensure we can import our modules
sys.path.insert(0, str(Path(__file__).parent))


# ═══════════════════════════════════════════════════════════════════════════
# COLORS & STYLING - European minimal aesthetic
# ═══════════════════════════════════════════════════════════════════════════

class Colors:
    """Muted, professional colors (European design)."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"

    # Muted palette
    SLATE = "\033[38;5;67m"       # Muted blue
    SAGE = "\033[38;5;108m"       # Muted green
    WARM = "\033[38;5;180m"       # Warm sand
    CORAL = "\033[38;5;174m"      # Soft coral
    MIST = "\033[38;5;250m"       # Light gray

    # Status colors
    SUCCESS = "\033[38;5;108m"   # Sage
    WARNING = "\033[38;5;180m"   # Warm
    ERROR = "\033[38;5;174m"     # Coral
    INFO = "\033[38;5;67m"       # Slate


def styled(text: str, *styles) -> str:
    """Apply styles to text."""
    prefix = "".join(styles)
    return f"{prefix}{text}{Colors.RESET}"


def print_thinking(text: str):
    """Print thinking text with animation."""
    print(styled(f"  💭 {text}", Colors.DIM, Colors.SLATE))
    time.sleep(0.1)  # Brief pause for effect


def print_success(text: str):
    """Print success message."""
    print(styled(f"  ✓ {text}", Colors.SUCCESS))


def print_warning(text: str):
    """Print warning message."""
    print(styled(f"  ⚠ {text}", Colors.WARNING))


def print_error(text: str):
    """Print error message."""
    print(styled(f"  ✗ {text}", Colors.ERROR))


def print_section(title: str):
    """Print section header."""
    print()
    print(styled(f"─── {title} ", Colors.SLATE) + styled("─" * (60 - len(title)), Colors.DIM))


def print_citation(source: str, confidence: float):
    """Print a citation."""
    conf_pct = int(confidence * 100)
    print(styled(f"     📚 {source} ({conf_pct}% match)", Colors.DIM))


# ═══════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════

def print_banner():
    """Print the TestAI banner with European minimal design."""
    banner = f"""
{styled("╔════════════════════════════════════════════════════════════╗", Colors.SLATE)}
{styled("║", Colors.SLATE)}                                                            {styled("║", Colors.SLATE)}
{styled("║", Colors.SLATE)}   {styled("TestAI Agent", Colors.BOLD, Colors.WARM)}                                        {styled("║", Colors.SLATE)}
{styled("║", Colors.SLATE)}   {styled("Your QA colleague that never sleeps", Colors.DIM)}                  {styled("║", Colors.SLATE)}
{styled("║", Colors.SLATE)}                                                            {styled("║", Colors.SLATE)}
{styled("║", Colors.SLATE)}   {styled("• Citation-aware reasoning (zero hallucination)", Colors.SAGE)}       {styled("║", Colors.SLATE)}
{styled("║", Colors.SLATE)}   {styled("• Visible thinking (watch the agent reason)", Colors.SAGE)}           {styled("║", Colors.SLATE)}
{styled("║", Colors.SLATE)}   {styled("• 10 API calls max (cost-conscious design)", Colors.SAGE)}            {styled("║", Colors.SLATE)}
{styled("║", Colors.SLATE)}                                                            {styled("║", Colors.SLATE)}
{styled("╚════════════════════════════════════════════════════════════╝", Colors.SLATE)}
    """
    print(banner)


# ═══════════════════════════════════════════════════════════════════════════
# COMMANDS
# ═══════════════════════════════════════════════════════════════════════════

def run_demo():
    """Run the interactive demo (no API needed)."""
    from demo import run_demo as demo_main
    demo_main()


def run_cli():
    """Run the full interactive CLI (requires API)."""
    from cli import main as cli_main
    asyncio.run(cli_main())


async def generate_tests(
    feature: str,
    offline: bool = False,
    page_type: Optional[str] = None,
    show_thinking: bool = True,
):
    """Generate tests for a feature with visible reasoning."""
    print_section(f"Generating tests for: {feature}")

    if offline:
        print(styled("  Mode: Offline (templates only)", Colors.DIM))
        await _generate_offline(feature, page_type)
    else:
        print(styled("  Mode: AI-powered with citation tracking", Colors.DIM))
        await _generate_with_reasoning(feature, page_type, show_thinking)


async def _generate_offline(feature: str, page_type: Optional[str]):
    """Generate tests using templates only."""
    from generators.prompts import get_template_tests
    from understanding.feature_analyzer import FeatureAnalyzer

    print_thinking("Analyzing feature request...")

    analyzer = FeatureAnalyzer()
    context = analyzer.from_request(feature)

    detected_type = page_type or context.page_type or "form"
    print_thinking(f"Detected page type: {detected_type}")

    tests = get_template_tests(detected_type, context.feature_name)

    if tests:
        print_section(f"Generated {len(tests)} test cases")

        for i, test in enumerate(tests, 1):
            priority = test.get("priority", "medium")
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(priority, "⚪")
            print(f"  {icon} TC-{i:03d}: {test.get('title', 'Test')}")

        print()
        export = input(styled("  Export to JSON? (y/n): ", Colors.DIM)).strip().lower()
        if export in ["y", "yes"]:
            import json
            filename = f"tests_{detected_type}.json"
            with open(filename, "w") as f:
                json.dump(tests, f, indent=2)
            print_success(f"Exported to {filename}")
    else:
        print_warning("No templates available for this feature type.")
        print(styled("  Try: login, signup, checkout, search, form", Colors.DIM))


async def _generate_with_reasoning(
    feature: str,
    page_type: Optional[str],
    show_thinking: bool,
):
    """Generate tests with citation-aware reasoning."""
    from cortex.reasoner import Reasoner
    from connectors.llm_gateway import create_gateway

    # Create gateway with strict limits
    gateway = create_gateway(
        deepseek_key=os.environ.get("DEEPSEEK_API_KEY", "sk-c104455631bb433b801fc4a16042419c"),
        max_calls=10,
    )

    # Check if we can make calls
    if not gateway.can_call():
        print_error("API call limit reached!")
        print(gateway.format_usage_status())
        return

    # Show remaining calls
    remaining = gateway.get_remaining_calls()
    print(styled(f"  API calls remaining: {remaining}/10", Colors.DIM))
    print()

    # Create reasoner
    reasoner = Reasoner(gateway=gateway)

    if show_thinking:
        print_thinking("Initializing QA Brain...")

    # Reason about the feature
    result = await reasoner.reason_about_feature(
        feature=feature,
        page_type=page_type,
        user_request="Generate comprehensive tests with focus on edge cases",
    )

    # Show thinking process
    if show_thinking and result.thinking:
        print_section("Thinking Process")
        for line in result.thinking.split("\n"):
            if line.strip():
                print(styled(f"  {line}", Colors.DIM, Colors.SLATE))

    # Show confidence
    print_section("Confidence Assessment")
    conf = result.confidence
    level_colors = {
        "very_high": Colors.SUCCESS,
        "high": Colors.SUCCESS,
        "moderate": Colors.WARNING,
        "low": Colors.ERROR,
        "very_low": Colors.ERROR,
    }
    color = level_colors.get(conf.level.value, Colors.MIST)
    print(styled(f"  {conf.level.value.upper()}: {conf.score:.0%}", color, Colors.BOLD))
    print(styled(f"  {conf.reasoning}", Colors.DIM))

    # Show citations
    if result.citations:
        print_section("Sources Used (Zero Hallucination)")
        for citation in result.citations[:5]:
            print_citation(citation.source, citation.confidence)

    # Show generated tests
    print_section("Generated Test Cases")
    print()
    print(result.output)

    # Show usage summary
    print_section("Usage Summary")
    print(gateway.format_usage_status())


async def analyze_security(
    feature: str,
    page_type: Optional[str] = None,
    show_thinking: bool = True,
):
    """Perform security-focused analysis."""
    print_section(f"Security Analysis: {feature}")

    from cortex.reasoner import Reasoner
    from connectors.llm_gateway import create_gateway

    gateway = create_gateway(max_calls=10)

    if not gateway.can_call():
        print_error("API call limit reached!")
        return

    remaining = gateway.get_remaining_calls()
    print(styled(f"  API calls remaining: {remaining}/10", Colors.DIM))

    reasoner = Reasoner(gateway=gateway)

    if show_thinking:
        print_thinking("Loading security knowledge from Brain...")

    result = await reasoner.analyze_security(
        feature=feature,
        page_type=page_type,
    )

    # Show thinking
    if show_thinking and result.thinking:
        print_section("Analysis Process")
        for line in result.thinking.split("\n"):
            if line.strip():
                print(styled(f"  {line}", Colors.DIM))

    # Show citations
    if result.citations:
        print_section("Security Knowledge Sources")
        for citation in result.citations[:5]:
            print_citation(citation.source, citation.confidence)

    # Show analysis
    print_section("Security Analysis")
    print()
    print(result.output)

    # Usage summary
    print_section("Usage Summary")
    print(gateway.format_usage_status())


def show_status():
    """Show system status with European minimal design."""
    print_section("System Status")

    # Check modules
    modules = [
        ("Brain (ChromaDB)", "brain.vector_store", "QABrain"),
        ("Gateway (Multi-LLM)", "connectors.llm_gateway", "LLMGateway"),
        ("Reasoner (Citations)", "cortex.reasoner", "Reasoner"),
        ("Cortex (Decision)", "cortex.decision_engine", "DecisionEngine"),
        ("Personality (UX)", "personality.tone", "ResponseStyler"),
        ("Generators", "generators.test_generator", "TestGenerator"),
        ("Understanding", "understanding.feature_analyzer", "FeatureAnalyzer"),
        ("Conversation", "conversation.interface", "Conversation"),
    ]

    for name, module, cls in modules:
        try:
            mod = __import__(module, fromlist=[cls])
            getattr(mod, cls)
            print_success(name)
        except Exception as e:
            print_error(f"{name} - {str(e)[:40]}")

    print_section("Configuration")

    # Check API key
    api_key = os.environ.get("DEEPSEEK_API_KEY", "sk-c104455631bb433b801fc4a16042419c")
    if api_key:
        print_success(f"API Key configured (ends with ...{api_key[-4:]})")
    else:
        print_warning("No API key set (using default test key)")

    # Check brain data
    brain_path = Path("./.brain_data")
    if brain_path.exists():
        print_success(f"Brain data exists at {brain_path}")
    else:
        print_warning("Brain not initialized (run: python -m brain.ingest)")

    print()


def show_usage():
    """Show API usage status."""
    print_section("API Usage Status")

    from connectors.llm_gateway import create_gateway

    gateway = create_gateway(max_calls=10)
    print(gateway.format_usage_status())

    if gateway.can_call():
        remaining = gateway.get_remaining_calls()
        print()
        print_success(f"You can make {remaining} more API calls this session")
    else:
        print()
        print_error("Call limit reached. Reset after 24 hours or restart.")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="TestAI Agent - Your intelligent QA colleague",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py demo                      # Interactive demo (no API)
  python main.py cli                       # Full CLI with AI
  python main.py generate "login page"     # Generate tests with reasoning
  python main.py generate "login" --offline  # Templates only
  python main.py security "checkout"       # Security analysis
  python main.py status                    # Show system status
  python main.py usage                     # Show API usage

Note: DeepSeek API is limited to 10 calls max per session.
        """,
    )

    parser.add_argument(
        "command",
        choices=["demo", "cli", "generate", "security", "status", "usage"],
        help="Command to run",
    )

    parser.add_argument(
        "feature",
        nargs="?",
        help="Feature to test (for 'generate' and 'security' commands)",
    )

    parser.add_argument(
        "--offline",
        action="store_true",
        help="Use templates only, no API calls",
    )

    parser.add_argument(
        "--page-type", "-t",
        help="Page type (login, signup, checkout, search, form)",
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Don't show the banner",
    )

    parser.add_argument(
        "--no-thinking",
        action="store_true",
        help="Don't show thinking process",
    )

    args = parser.parse_args()

    # Show banner
    if not args.no_banner and args.command not in ["status", "usage"]:
        print_banner()

    # Run command
    if args.command == "demo":
        run_demo()

    elif args.command == "cli":
        run_cli()

    elif args.command == "generate":
        if not args.feature:
            print_error("Please specify a feature to test")
            print(styled("  Example: python main.py generate 'login page'", Colors.DIM))
            sys.exit(1)

        asyncio.run(generate_tests(
            feature=args.feature,
            offline=args.offline,
            page_type=args.page_type,
            show_thinking=not args.no_thinking,
        ))

    elif args.command == "security":
        if not args.feature:
            print_error("Please specify a feature to analyze")
            print(styled("  Example: python main.py security 'checkout page'", Colors.DIM))
            sys.exit(1)

        asyncio.run(analyze_security(
            feature=args.feature,
            page_type=args.page_type,
            show_thinking=not args.no_thinking,
        ))

    elif args.command == "status":
        show_status()

    elif args.command == "usage":
        show_usage()


if __name__ == "__main__":
    main()
