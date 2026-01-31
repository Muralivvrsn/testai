"""
TestAI Agent - Rich Output Module

Beautiful terminal output using Rich library (fallback to basic if not installed).
European design: clean, minimal, professional.
"""

from typing import Optional, List, Dict, Any
import sys

# Try to import rich, fallback to basic output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.markdown import Markdown
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.style import Style
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# European muted color palette
COLORS = {
    "primary": "#5B7C99",      # Slate blue
    "success": "#6B8E6B",      # Sage green
    "warning": "#C4A35A",      # Warm sand
    "error": "#C47A7A",        # Soft coral
    "muted": "#8B8B8B",        # Gray
    "accent": "#7A9CC4",       # Light blue
}


class RichOutput:
    """
    Rich terminal output with European minimal design.

    Falls back to basic output if Rich is not installed.

    Usage:
        output = RichOutput()
        output.header("Test Assessment")
        output.thinking("Analyzing page structure...")
        output.success("Found 5 test scenarios")
        output.table(headers=["Priority", "Count"], rows=[["Critical", "3"]])
    """

    def __init__(self, force_basic: bool = False):
        """
        Initialize output.

        Args:
            force_basic: Force basic output even if Rich is available
        """
        self.use_rich = RICH_AVAILABLE and not force_basic

        if self.use_rich:
            self.console = Console()
        else:
            self.console = None

    def header(self, text: str, subtitle: Optional[str] = None):
        """Print a header."""
        if self.use_rich:
            title_text = Text(text, style=f"bold {COLORS['primary']}")
            if subtitle:
                content = f"[{COLORS['muted']}]{subtitle}[/]"
                self.console.print(Panel(
                    content,
                    title=title_text,
                    border_style=COLORS['primary'],
                    box=box.ROUNDED,
                    padding=(1, 2),
                ))
            else:
                self.console.print()
                self.console.print(title_text)
                self.console.print("─" * 50, style=COLORS['muted'])
        else:
            print()
            print("=" * 50)
            print(text)
            if subtitle:
                print(subtitle)
            print("=" * 50)

    def section(self, title: str):
        """Print a section header."""
        if self.use_rich:
            self.console.print()
            self.console.print(f"[{COLORS['primary']}]─── {title} [/]" + "─" * (40 - len(title)), style=COLORS['muted'])
        else:
            print()
            print(f"─── {title} " + "─" * (40 - len(title)))

    def thinking(self, text: str):
        """Print a thinking message."""
        if self.use_rich:
            self.console.print(f"  [dim]💭 {text}[/dim]")
        else:
            print(f"  💭 {text}")

    def success(self, text: str):
        """Print a success message."""
        if self.use_rich:
            self.console.print(f"  [{COLORS['success']}]✓ {text}[/]")
        else:
            print(f"  ✓ {text}")

    def warning(self, text: str):
        """Print a warning message."""
        if self.use_rich:
            self.console.print(f"  [{COLORS['warning']}]⚠ {text}[/]")
        else:
            print(f"  ⚠ {text}")

    def error(self, text: str):
        """Print an error message."""
        if self.use_rich:
            self.console.print(f"  [{COLORS['error']}]✗ {text}[/]")
        else:
            print(f"  ✗ {text}")

    def info(self, text: str):
        """Print an info message."""
        if self.use_rich:
            self.console.print(f"  [{COLORS['muted']}]{text}[/]")
        else:
            print(f"  {text}")

    def citation(self, source: str, confidence: float):
        """Print a citation (zero hallucination)."""
        conf_pct = int(confidence * 100)
        if self.use_rich:
            self.console.print(f"     [{COLORS['muted']}]📚 {source} ({conf_pct}% match)[/]")
        else:
            print(f"     📚 {source} ({conf_pct}% match)")

    def table(
        self,
        headers: List[str],
        rows: List[List[str]],
        title: Optional[str] = None,
    ):
        """Print a table."""
        if self.use_rich:
            table = Table(
                title=title,
                box=box.SIMPLE,
                header_style=f"bold {COLORS['primary']}",
                border_style=COLORS['muted'],
            )

            for header in headers:
                table.add_column(header)

            for row in rows:
                table.add_row(*row)

            self.console.print(table)
        else:
            # Basic table output
            if title:
                print(f"\n{title}")
                print("-" * 40)

            # Header
            print(" | ".join(headers))
            print("-" * 40)

            # Rows
            for row in rows:
                print(" | ".join(row))

    def priority_indicator(self, priority: str) -> str:
        """Get priority indicator."""
        icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
        }
        return icons.get(priority.lower(), "⚪")

    def risk_indicator(self, level: str) -> str:
        """Get risk indicator."""
        icons = {
            "critical": "🚨",
            "high": "⚠️",
            "moderate": "📋",
            "low": "✅",
        }
        return icons.get(level.lower(), "📋")

    def test_case(
        self,
        test_id: str,
        title: str,
        priority: str,
        category: Optional[str] = None,
        show_details: bool = False,
        steps: Optional[List[str]] = None,
        expected: Optional[str] = None,
    ):
        """Print a test case."""
        icon = self.priority_indicator(priority)

        if self.use_rich:
            self.console.print(f"  {icon} [bold]{test_id}[/]: {title}")
            if category:
                self.console.print(f"     [{COLORS['muted']}]{category.replace('_', ' ').title()}[/]")

            if show_details:
                if steps:
                    self.console.print(f"     [dim]Steps:[/dim]")
                    for i, step in enumerate(steps, 1):
                        self.console.print(f"       {i}. {step}")

                if expected:
                    self.console.print(f"     [dim]Expected:[/dim] {expected}")
        else:
            print(f"  {icon} {test_id}: {title}")
            if category:
                print(f"     {category.replace('_', ' ').title()}")

            if show_details:
                if steps:
                    print("     Steps:")
                    for i, step in enumerate(steps, 1):
                        print(f"       {i}. {step}")

                if expected:
                    print(f"     Expected: {expected}")

    def markdown(self, content: str):
        """Print markdown content."""
        if self.use_rich:
            self.console.print(Markdown(content))
        else:
            # Basic markdown-ish output
            for line in content.split('\n'):
                # Headers
                if line.startswith('# '):
                    print(f"\n{line[2:].upper()}")
                    print("=" * 40)
                elif line.startswith('## '):
                    print(f"\n{line[3:]}")
                    print("-" * 30)
                elif line.startswith('### '):
                    print(f"\n{line[4:]}")
                # Lists
                elif line.strip().startswith('- '):
                    print(f"  • {line.strip()[2:]}")
                elif line.strip().startswith('* '):
                    print(f"  • {line.strip()[2:]}")
                # Bold
                elif '**' in line:
                    # Simple bold removal
                    print(line.replace('**', ''))
                else:
                    print(line)

    def ask(self, question: str, options: Optional[List[str]] = None) -> str:
        """Ask a question."""
        if self.use_rich:
            self.console.print()
            self.console.print(f"[{COLORS['accent']}]❓ {question}[/]")

            if options:
                for i, opt in enumerate(options, 1):
                    self.console.print(f"   {i}. {opt}")
                self.console.print()

            return self.console.input(f"[{COLORS['muted']}]   → [/]")
        else:
            print()
            print(f"❓ {question}")

            if options:
                for i, opt in enumerate(options, 1):
                    print(f"   {i}. {opt}")
                print()

            return input("   → ")

    def confirm(self, question: str, default: bool = True) -> bool:
        """Ask for confirmation."""
        default_str = "Y/n" if default else "y/N"

        if self.use_rich:
            response = self.console.input(f"[{COLORS['muted']}]{question} [{default_str}]: [/]")
        else:
            response = input(f"{question} [{default_str}]: ")

        if not response:
            return default

        return response.lower() in ['y', 'yes']

    def progress(self, description: str):
        """Create a progress context manager."""
        if self.use_rich:
            return Progress(
                SpinnerColumn(),
                TextColumn(f"[{COLORS['primary']}]{description}[/]"),
                console=self.console,
            )
        else:
            # Fake progress for non-rich
            class FakeProgress:
                def __enter__(self):
                    print(f"  ⏳ {description}...")
                    return self

                def __exit__(self, *args):
                    print("  ✓ Done")

                def add_task(self, *args, **kwargs):
                    return 0

                def update(self, *args, **kwargs):
                    pass

            return FakeProgress()

    def divider(self):
        """Print a divider."""
        if self.use_rich:
            self.console.print(f"[{COLORS['muted']}]{'─' * 50}[/]")
        else:
            print("─" * 50)

    def newline(self):
        """Print a newline."""
        if self.use_rich:
            self.console.print()
        else:
            print()


# Global console instance
console = RichOutput()


# Quick helpers
def print_header(text: str, subtitle: Optional[str] = None):
    console.header(text, subtitle)

def print_thinking(text: str):
    console.thinking(text)

def print_success(text: str):
    console.success(text)

def print_warning(text: str):
    console.warning(text)

def print_error(text: str):
    console.error(text)

def print_citation(source: str, confidence: float):
    console.citation(source, confidence)
