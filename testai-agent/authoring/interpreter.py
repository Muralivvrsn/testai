"""
TestAI Agent - Natural Language Interpreter

Interprets natural language commands for test
management and execution.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import re


class CommandType(Enum):
    """Types of interpreted commands."""
    # Test management
    CREATE_TEST = "create_test"
    EDIT_TEST = "edit_test"
    DELETE_TEST = "delete_test"
    COPY_TEST = "copy_test"
    RENAME_TEST = "rename_test"

    # Execution
    RUN_TEST = "run_test"
    RUN_SUITE = "run_suite"
    RUN_TAG = "run_tag"
    STOP_EXECUTION = "stop_execution"

    # Query
    FIND_TESTS = "find_tests"
    SHOW_RESULTS = "show_results"
    SHOW_COVERAGE = "show_coverage"
    SHOW_FLAKY = "show_flaky"

    # Navigation
    OPEN_TEST = "open_test"
    GO_TO = "go_to"

    # Analysis
    ANALYZE_FAILURES = "analyze_failures"
    PREDICT_FAILURES = "predict_failures"
    SUGGEST_TESTS = "suggest_tests"

    # Help
    HELP = "help"
    EXPLAIN = "explain"

    # Unknown
    UNKNOWN = "unknown"


@dataclass
class CommandParameter:
    """A parameter extracted from a command."""
    name: str
    value: Any
    confidence: float


@dataclass
class InterpretedCommand:
    """An interpreted command."""
    command_type: CommandType
    parameters: List[CommandParameter]
    original_text: str
    confidence: float
    alternatives: List[CommandType] = field(default_factory=list)
    clarification_needed: bool = False
    clarification_question: Optional[str] = None


class NLInterpreter:
    """
    Interprets natural language commands.

    Features:
    - Command classification
    - Parameter extraction
    - Ambiguity detection
    - Context awareness
    """

    # Command patterns
    COMMAND_PATTERNS = {
        CommandType.CREATE_TEST: [
            r"create\s+(?:a\s+)?(?:new\s+)?test",
            r"add\s+(?:a\s+)?(?:new\s+)?test",
            r"write\s+(?:a\s+)?test",
            r"make\s+(?:a\s+)?test",
        ],
        CommandType.EDIT_TEST: [
            r"edit\s+(?:the\s+)?test",
            r"modify\s+(?:the\s+)?test",
            r"update\s+(?:the\s+)?test",
            r"change\s+(?:the\s+)?test",
        ],
        CommandType.DELETE_TEST: [
            r"delete\s+(?:the\s+)?test",
            r"remove\s+(?:the\s+)?test",
        ],
        CommandType.COPY_TEST: [
            r"copy\s+(?:the\s+)?test",
            r"duplicate\s+(?:the\s+)?test",
            r"clone\s+(?:the\s+)?test",
        ],
        CommandType.RENAME_TEST: [
            r"rename\s+(?:the\s+)?test",
        ],
        CommandType.RUN_TEST: [
            r"run\s+(?:the\s+)?test",
            r"execute\s+(?:the\s+)?test",
            r"start\s+(?:the\s+)?test",
        ],
        CommandType.RUN_SUITE: [
            r"run\s+(?:the\s+)?suite",
            r"run\s+all\s+tests?",
            r"execute\s+(?:the\s+)?suite",
        ],
        CommandType.RUN_TAG: [
            r"run\s+(?:tests?\s+)?(?:with\s+)?tag",
            r"run\s+(?:tests?\s+)?tagged",
        ],
        CommandType.STOP_EXECUTION: [
            r"stop\s+(?:the\s+)?(?:test|execution)",
            r"cancel\s+(?:the\s+)?(?:test|execution)",
            r"abort",
        ],
        CommandType.FIND_TESTS: [
            r"find\s+(?:the\s+)?tests?",
            r"search\s+(?:for\s+)?tests?",
            r"list\s+(?:the\s+)?tests?",
            r"show\s+(?:me\s+)?tests?",
        ],
        CommandType.SHOW_RESULTS: [
            r"show\s+(?:the\s+)?results?",
            r"what\s+(?:are\s+)?(?:the\s+)?results?",
            r"display\s+(?:the\s+)?results?",
        ],
        CommandType.SHOW_COVERAGE: [
            r"show\s+(?:the\s+)?coverage",
            r"what\s+(?:is\s+)?(?:the\s+)?coverage",
            r"coverage\s+report",
        ],
        CommandType.SHOW_FLAKY: [
            r"show\s+(?:the\s+)?flaky",
            r"find\s+(?:the\s+)?flaky",
            r"which\s+tests?\s+(?:are\s+)?flaky",
        ],
        CommandType.OPEN_TEST: [
            r"open\s+(?:the\s+)?test",
            r"view\s+(?:the\s+)?test",
        ],
        CommandType.ANALYZE_FAILURES: [
            r"analyze\s+(?:the\s+)?failures?",
            r"why\s+did\s+(?:the\s+)?test\s+fail",
            r"what\s+(?:caused|caused)\s+(?:the\s+)?failure",
        ],
        CommandType.PREDICT_FAILURES: [
            r"predict\s+(?:the\s+)?failures?",
            r"which\s+tests?\s+(?:will|might)\s+fail",
        ],
        CommandType.SUGGEST_TESTS: [
            r"suggest\s+(?:some\s+)?tests?",
            r"what\s+tests?\s+(?:should|do)\s+(?:I|we)\s+(?:add|write)",
            r"recommend\s+tests?",
        ],
        CommandType.HELP: [
            r"^help$",
            r"what\s+can\s+(?:you|I)\s+do",
            r"show\s+(?:me\s+)?(?:the\s+)?commands?",
        ],
        CommandType.EXPLAIN: [
            r"explain\s+(?:the\s+)?test",
            r"what\s+does\s+(?:this\s+)?test\s+do",
            r"describe\s+(?:the\s+)?test",
        ],
    }

    # Parameter extraction patterns
    PARAM_PATTERNS = {
        "test_name": [
            r"(?:test|named?)\s+['\"](.+?)['\"]",
            r"(?:test|named?)\s+(\w+)",
            r"['\"](.+?)['\"]",
        ],
        "tag": [
            r"tag(?:ged)?\s+['\"]?(\w+)['\"]?",
            r"@(\w+)",
        ],
        "count": [
            r"(\d+)\s+tests?",
            r"top\s+(\d+)",
        ],
        "time_range": [
            r"(?:last|past)\s+(\d+)\s+(hours?|days?|weeks?)",
        ],
        "status": [
            r"(passed|failed|flaky|skipped)",
        ],
    }

    def __init__(self):
        """Initialize the interpreter."""
        self._compiled_commands = self._compile_patterns(self.COMMAND_PATTERNS)
        self._compiled_params = self._compile_patterns(self.PARAM_PATTERNS)
        self._context: Dict[str, Any] = {}
        self._handlers: Dict[CommandType, Callable] = {}

    def _compile_patterns(self, patterns: Dict) -> Dict:
        """Compile regex patterns."""
        compiled = {}
        for key, pattern_list in patterns.items():
            compiled[key] = [re.compile(p, re.IGNORECASE) for p in pattern_list]
        return compiled

    def interpret(self, text: str) -> InterpretedCommand:
        """Interpret a natural language command."""
        text = text.strip()

        if not text:
            return InterpretedCommand(
                command_type=CommandType.UNKNOWN,
                parameters=[],
                original_text=text,
                confidence=0.0,
            )

        # Detect command type
        command_type, confidence, alternatives = self._detect_command(text)

        # Extract parameters
        parameters = self._extract_parameters(text)

        # Check if clarification is needed
        clarification_needed = False
        clarification_question = None

        if confidence < 0.5:
            clarification_needed = True
            if alternatives:
                options = [a.value for a in alternatives[:3]]
                clarification_question = f"Did you mean: {', '.join(options)}?"
            else:
                clarification_question = "Could you please rephrase your request?"

        # Check for missing required parameters
        required_params = self._get_required_params(command_type)
        missing = [p for p in required_params if not any(param.name == p for param in parameters)]

        if missing and command_type != CommandType.UNKNOWN:
            clarification_needed = True
            clarification_question = f"Please specify: {', '.join(missing)}"

        return InterpretedCommand(
            command_type=command_type,
            parameters=parameters,
            original_text=text,
            confidence=confidence,
            alternatives=alternatives,
            clarification_needed=clarification_needed,
            clarification_question=clarification_question,
        )

    def _detect_command(
        self,
        text: str,
    ) -> tuple[CommandType, float, List[CommandType]]:
        """Detect command type from text."""
        scores: Dict[CommandType, float] = {}

        for command_type, patterns in self._compiled_commands.items():
            for pattern in patterns:
                if pattern.search(text):
                    current = scores.get(command_type, 0)
                    scores[command_type] = max(current, 0.8)

        if not scores:
            # Try fuzzy matching
            text_lower = text.lower()
            keywords = {
                CommandType.RUN_TEST: ["run", "execute", "start"],
                CommandType.CREATE_TEST: ["create", "add", "new", "write"],
                CommandType.FIND_TESTS: ["find", "search", "list", "show"],
                CommandType.HELP: ["help", "?"],
            }

            for cmd, words in keywords.items():
                for word in words:
                    if word in text_lower:
                        scores[cmd] = scores.get(cmd, 0) + 0.3

        if not scores:
            return CommandType.UNKNOWN, 0.2, []

        # Sort by score
        sorted_commands = sorted(
            scores.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        best_command = sorted_commands[0][0]
        best_score = sorted_commands[0][1]

        # Get alternatives
        alternatives = [cmd for cmd, score in sorted_commands[1:4] if score > 0.3]

        return best_command, best_score, alternatives

    def _extract_parameters(self, text: str) -> List[CommandParameter]:
        """Extract parameters from text."""
        parameters = []

        for param_name, patterns in self._compiled_params.items():
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    value = match.group(1)

                    # Convert numeric values
                    if param_name == "count":
                        value = int(value)

                    parameters.append(CommandParameter(
                        name=param_name,
                        value=value,
                        confidence=0.8,
                    ))
                    break  # Only one match per parameter type

        return parameters

    def _get_required_params(self, command_type: CommandType) -> List[str]:
        """Get required parameters for a command type."""
        required = {
            CommandType.CREATE_TEST: [],
            CommandType.EDIT_TEST: ["test_name"],
            CommandType.DELETE_TEST: ["test_name"],
            CommandType.RUN_TEST: ["test_name"],
            CommandType.RUN_TAG: ["tag"],
            CommandType.OPEN_TEST: ["test_name"],
        }

        return required.get(command_type, [])

    def set_context(self, key: str, value: Any):
        """Set context for interpretation."""
        self._context[key] = value

    def get_context(self, key: str) -> Optional[Any]:
        """Get context value."""
        return self._context.get(key)

    def register_handler(
        self,
        command_type: CommandType,
        handler: Callable,
    ):
        """Register a command handler."""
        self._handlers[command_type] = handler

    def execute(self, command: InterpretedCommand) -> Any:
        """Execute an interpreted command."""
        handler = self._handlers.get(command.command_type)
        if handler:
            params = {p.name: p.value for p in command.parameters}
            return handler(**params)
        return None

    def get_help(self) -> str:
        """Get help text for all commands."""
        lines = [
            "=" * 60,
            "  AVAILABLE COMMANDS",
            "=" * 60,
            "",
        ]

        categories = {
            "Test Management": [
                (CommandType.CREATE_TEST, "Create a new test", "create test 'Login Flow'"),
                (CommandType.EDIT_TEST, "Edit an existing test", "edit test 'Login Flow'"),
                (CommandType.DELETE_TEST, "Delete a test", "delete test 'Login Flow'"),
                (CommandType.COPY_TEST, "Copy a test", "copy test 'Login Flow'"),
            ],
            "Execution": [
                (CommandType.RUN_TEST, "Run a specific test", "run test 'Login Flow'"),
                (CommandType.RUN_SUITE, "Run all tests", "run all tests"),
                (CommandType.RUN_TAG, "Run tests by tag", "run tests tagged @smoke"),
                (CommandType.STOP_EXECUTION, "Stop execution", "stop execution"),
            ],
            "Query": [
                (CommandType.FIND_TESTS, "Find tests", "find tests for 'login'"),
                (CommandType.SHOW_RESULTS, "Show results", "show results"),
                (CommandType.SHOW_COVERAGE, "Show coverage", "show coverage"),
                (CommandType.SHOW_FLAKY, "Show flaky tests", "show flaky tests"),
            ],
            "Analysis": [
                (CommandType.ANALYZE_FAILURES, "Analyze failures", "analyze failures"),
                (CommandType.PREDICT_FAILURES, "Predict failures", "predict failures"),
                (CommandType.SUGGEST_TESTS, "Suggest tests", "suggest tests for Login"),
            ],
        }

        for category, commands in categories.items():
            lines.extend([
                f"  {category}:",
                "-" * 60,
            ])

            for cmd, description, example in commands:
                lines.extend([
                    f"    {cmd.value}",
                    f"      {description}",
                    f"      Example: {example}",
                    "",
                ])

        lines.append("=" * 60)
        return "\n".join(lines)

    def format_command(self, command: InterpretedCommand) -> str:
        """Format interpreted command for display."""
        lines = [
            "=" * 60,
            "  INTERPRETED COMMAND",
            "=" * 60,
            "",
            f"  Type: {command.command_type.value}",
            f"  Confidence: {command.confidence:.1%}",
            f"  Original: {command.original_text[:50]}",
            "",
        ]

        if command.parameters:
            lines.append("  Parameters:")
            for param in command.parameters:
                lines.append(f"    - {param.name}: {param.value}")
            lines.append("")

        if command.alternatives:
            lines.append("  Alternatives:")
            for alt in command.alternatives:
                lines.append(f"    - {alt.value}")
            lines.append("")

        if command.clarification_needed:
            lines.extend([
                "  ⚠️ Clarification Needed:",
                f"    {command.clarification_question}",
            ])

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_nl_interpreter() -> NLInterpreter:
    """Create a natural language interpreter instance."""
    return NLInterpreter()
