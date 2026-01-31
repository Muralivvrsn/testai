"""
TestAI Agent - Smart Brain Ingestion

Parses QA_BRAIN.md intelligently:
- Detects section hierarchy (# > ## > ###)
- Extracts test patterns and rules
- Tags content for precise retrieval
- Creates citation-ready chunks

Design: European precision - every piece of knowledge is catalogued.
"""

import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum


class ContentType(Enum):
    """Types of content in the Brain."""
    SECTION_HEADER = "section_header"
    TEST_CASE = "test_case"
    RULE = "rule"
    EXAMPLE = "example"
    CHECKLIST = "checklist"
    DESCRIPTION = "description"


@dataclass
class BrainSection:
    """A section of the QA Brain."""
    id: str                    # e.g., "7.1"
    title: str                 # e.g., "Email Validation"
    level: int                 # Header level (1-4)
    full_path: str             # e.g., "Login Page > Email Validation"
    content: str               # Raw content
    parent_id: Optional[str] = None
    children: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    checklist_items: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "level": self.level,
            "full_path": self.full_path,
            "content": self.content[:500],  # Truncate for preview
            "parent_id": self.parent_id,
            "children": self.children,
            "tags": self.tags,
            "rules": self.rules,
            "examples": self.examples,
            "checklist_items": self.checklist_items,
        }


@dataclass
class BrainChunk:
    """A chunk ready for vector storage."""
    id: str
    section_id: str
    section_title: str
    full_path: str
    content: str
    content_type: ContentType
    tags: List[str]
    metadata: Dict[str, Any]

    def to_embedding_text(self) -> str:
        """Get text for embedding."""
        return f"{self.full_path}\n{self.content}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "section_id": self.section_id,
            "section_title": self.section_title,
            "full_path": self.full_path,
            "content": self.content,
            "content_type": self.content_type.value,
            "tags": self.tags,
            "metadata": self.metadata,
        }


class SmartBrainIngestor:
    """
    Intelligent parser for QA_BRAIN.md.

    Features:
    - Hierarchical section detection
    - Rule and pattern extraction
    - Automatic tagging
    - Citation-ready output

    Usage:
        ingestor = SmartBrainIngestor()
        result = ingestor.ingest("QA_BRAIN.md")

        # Get all sections
        for section in result.sections:
            print(f"{section.id}: {section.title}")

        # Get chunks for vector store
        for chunk in result.chunks:
            print(f"{chunk.full_path}: {chunk.content_type.value}")
    """

    # Patterns for detecting content types
    RULE_PATTERNS = [
        r"^\s*[-*]\s+Test\s+",           # - Test ...
        r"^\s*[-*]\s+Verify\s+",          # - Verify ...
        r"^\s*[-*]\s+Check\s+",           # - Check ...
        r"^\s*[-*]\s+Ensure\s+",          # - Ensure ...
        r"^\s*[-*]\s+Validate\s+",        # - Validate ...
        r"^\s*\d+\.\s+Test\s+",           # 1. Test ...
        r"^\s*\d+\.\s+Verify\s+",         # 1. Verify ...
    ]

    EXAMPLE_PATTERNS = [
        r"^\s*Example:",
        r"^\s*For example:",
        r"^\s*E\.g\.",
        r"^\s*```",  # Code blocks
    ]

    CHECKLIST_PATTERNS = [
        r"^\s*\[ \]",                     # [ ] Unchecked
        r"^\s*\[x\]",                     # [x] Checked
        r"^\s*\[X\]",                     # [X] Checked
    ]

    # Keywords for automatic tagging
    TAG_KEYWORDS = {
        "security": ["security", "injection", "xss", "csrf", "auth", "password", "token", "session", "vulnerability"],
        "validation": ["validation", "validate", "valid", "invalid", "format", "required"],
        "accessibility": ["accessibility", "wcag", "aria", "screen reader", "keyboard", "focus"],
        "performance": ["performance", "speed", "load", "timeout", "latency"],
        "mobile": ["mobile", "responsive", "touch", "viewport"],
        "api": ["api", "endpoint", "request", "response", "http", "rest"],
        "database": ["database", "sql", "query", "data"],
        "ui": ["ui", "display", "layout", "style", "css", "visual"],
        "error": ["error", "exception", "failure", "crash"],
        "edge_case": ["edge case", "boundary", "limit", "maximum", "minimum"],
    }

    def __init__(self):
        """Initialize ingestor."""
        self.sections: Dict[str, BrainSection] = {}
        self.chunks: List[BrainChunk] = []
        self._section_counter = 0
        self._chunk_counter = 0

    def _next_section_id(self, level: int, parent_id: Optional[str] = None) -> str:
        """Generate next section ID."""
        self._section_counter += 1

        if parent_id:
            # Sub-section numbering
            parent = self.sections.get(parent_id)
            if parent:
                child_count = len(parent.children) + 1
                return f"{parent_id}.{child_count}"

        # Top-level section
        return str(self._section_counter)

    def _next_chunk_id(self) -> str:
        """Generate next chunk ID."""
        self._chunk_counter += 1
        return f"chunk-{self._chunk_counter:04d}"

    def _detect_tags(self, text: str) -> List[str]:
        """Detect tags from text content."""
        text_lower = text.lower()
        tags = []

        for tag, keywords in self.TAG_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                tags.append(tag)

        return tags

    def _detect_content_type(self, line: str) -> ContentType:
        """Detect content type of a line."""
        for pattern in self.RULE_PATTERNS:
            if re.match(pattern, line, re.IGNORECASE):
                return ContentType.RULE

        for pattern in self.EXAMPLE_PATTERNS:
            if re.match(pattern, line, re.IGNORECASE):
                return ContentType.EXAMPLE

        for pattern in self.CHECKLIST_PATTERNS:
            if re.match(pattern, line):
                return ContentType.CHECKLIST

        return ContentType.DESCRIPTION

    def _extract_rules(self, content: str) -> List[str]:
        """Extract test rules from content."""
        rules = []
        lines = content.split("\n")

        for line in lines:
            line = line.strip()
            if not line:
                continue

            for pattern in self.RULE_PATTERNS:
                if re.match(pattern, line, re.IGNORECASE):
                    # Clean up the rule
                    rule = re.sub(r"^\s*[-*\d.]+\s*", "", line)
                    rules.append(rule)
                    break

        return rules

    def _extract_checklist(self, content: str) -> List[str]:
        """Extract checklist items from content."""
        items = []
        lines = content.split("\n")

        for line in lines:
            for pattern in self.CHECKLIST_PATTERNS:
                if re.match(pattern, line.strip()):
                    # Clean up the item
                    item = re.sub(r"^\s*\[[ xX]\]\s*", "", line.strip())
                    items.append(item)
                    break

        return items

    def _parse_header(self, line: str) -> Tuple[int, str]:
        """Parse a markdown header line."""
        match = re.match(r"^(#+)\s+(.+)$", line.strip())
        if match:
            level = len(match.group(1))
            title = match.group(2).strip()
            return level, title
        return 0, ""

    def _build_full_path(self, section_id: str, title: str) -> str:
        """Build full path from section hierarchy."""
        parts = [title]
        current_id = section_id

        while "." in current_id:
            parent_id = current_id.rsplit(".", 1)[0]
            parent = self.sections.get(parent_id)
            if parent:
                parts.insert(0, parent.title)
            current_id = parent_id

        return " > ".join(parts)

    def ingest(self, filepath: str) -> "IngestResult":
        """
        Ingest a QA Brain markdown file.

        Args:
            filepath: Path to QA_BRAIN.md

        Returns:
            IngestResult with sections and chunks
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Brain file not found: {filepath}")

        content = path.read_text(encoding="utf-8")
        return self.ingest_content(content)

    def ingest_content(self, content: str) -> "IngestResult":
        """
        Ingest content directly.

        Args:
            content: Markdown content

        Returns:
            IngestResult with sections and chunks
        """
        self.sections = {}
        self.chunks = []
        self._section_counter = 0
        self._chunk_counter = 0

        lines = content.split("\n")
        current_section: Optional[BrainSection] = None
        current_content: List[str] = []
        section_stack: List[str] = []  # Stack of parent section IDs

        for line in lines:
            # Check for header
            level, title = self._parse_header(line)

            if level > 0 and title:
                # Save previous section
                if current_section:
                    self._finalize_section(current_section, current_content)
                    current_content = []

                # Determine parent
                while section_stack and self.sections[section_stack[-1]].level >= level:
                    section_stack.pop()

                parent_id = section_stack[-1] if section_stack else None

                # Create new section
                section_id = self._next_section_id(level, parent_id)
                full_path = self._build_full_path(section_id, title)

                current_section = BrainSection(
                    id=section_id,
                    title=title,
                    level=level,
                    full_path=full_path,
                    content="",
                    parent_id=parent_id,
                )

                self.sections[section_id] = current_section

                # Update parent's children
                if parent_id and parent_id in self.sections:
                    self.sections[parent_id].children.append(section_id)

                section_stack.append(section_id)

            elif current_section:
                # Add to current section content
                current_content.append(line)

        # Finalize last section
        if current_section:
            self._finalize_section(current_section, current_content)

        return IngestResult(
            sections=list(self.sections.values()),
            chunks=self.chunks,
            stats={
                "total_sections": len(self.sections),
                "total_chunks": len(self.chunks),
                "top_level_sections": len([s for s in self.sections.values() if s.level == 1]),
            },
        )

    def _finalize_section(self, section: BrainSection, content_lines: List[str]):
        """Finalize a section with its content."""
        content = "\n".join(content_lines).strip()
        section.content = content

        # Extract structured data
        section.rules = self._extract_rules(content)
        section.checklist_items = self._extract_checklist(content)
        section.tags = self._detect_tags(f"{section.title} {content}")

        # Create chunks
        self._create_chunks_from_section(section)

    def _create_chunks_from_section(self, section: BrainSection):
        """Create vector-ready chunks from a section."""
        # Main section chunk
        if section.content:
            chunk = BrainChunk(
                id=self._next_chunk_id(),
                section_id=section.id,
                section_title=section.title,
                full_path=section.full_path,
                content=section.content[:1000],  # Limit chunk size
                content_type=ContentType.SECTION_HEADER,
                tags=section.tags,
                metadata={
                    "level": section.level,
                    "has_rules": len(section.rules) > 0,
                    "rule_count": len(section.rules),
                },
            )
            self.chunks.append(chunk)

        # Individual rule chunks (for precise retrieval)
        for i, rule in enumerate(section.rules):
            chunk = BrainChunk(
                id=self._next_chunk_id(),
                section_id=section.id,
                section_title=section.title,
                full_path=f"{section.full_path} > Rule {i+1}",
                content=rule,
                content_type=ContentType.RULE,
                tags=section.tags + self._detect_tags(rule),
                metadata={
                    "rule_index": i,
                    "parent_section": section.id,
                },
            )
            self.chunks.append(chunk)


@dataclass
class IngestResult:
    """Result of brain ingestion."""
    sections: List[BrainSection]
    chunks: List[BrainChunk]
    stats: Dict[str, int]

    def get_section(self, section_id: str) -> Optional[BrainSection]:
        """Get section by ID."""
        for section in self.sections:
            if section.id == section_id:
                return section
        return None

    def get_chunks_for_section(self, section_id: str) -> List[BrainChunk]:
        """Get all chunks for a section."""
        return [c for c in self.chunks if c.section_id == section_id]

    def get_rules(self) -> List[BrainChunk]:
        """Get all rule chunks."""
        return [c for c in self.chunks if c.content_type == ContentType.RULE]

    def get_by_tag(self, tag: str) -> List[BrainChunk]:
        """Get chunks by tag."""
        return [c for c in self.chunks if tag in c.tags]

    def summary(self) -> str:
        """Get human-readable summary."""
        lines = []
        lines.append("Brain Ingestion Summary")
        lines.append("=" * 40)
        lines.append(f"Total Sections: {self.stats['total_sections']}")
        lines.append(f"Total Chunks: {self.stats['total_chunks']}")
        lines.append(f"Top-Level Sections: {self.stats['top_level_sections']}")
        lines.append("")

        lines.append("Sections:")
        for section in self.sections:
            indent = "  " * (section.level - 1)
            rule_count = f" ({len(section.rules)} rules)" if section.rules else ""
            lines.append(f"{indent}[{section.id}] {section.title}{rule_count}")

        lines.append("")
        lines.append("Tags Found:")
        all_tags = set()
        for chunk in self.chunks:
            all_tags.update(chunk.tags)
        for tag in sorted(all_tags):
            count = len(self.get_by_tag(tag))
            lines.append(f"  - {tag}: {count} chunks")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

def ingest_brain(filepath: str) -> IngestResult:
    """Quick ingest a Brain file."""
    ingestor = SmartBrainIngestor()
    return ingestor.ingest(filepath)


def ingest_brain_content(content: str) -> IngestResult:
    """Quick ingest Brain content."""
    ingestor = SmartBrainIngestor()
    return ingestor.ingest_content(content)


if __name__ == "__main__":
    # Demo with sample content
    sample_brain = """
# QA Testing Knowledge Base

## Input Validation

### Email Validation
- Test valid email format (user@domain.com)
- Test invalid email format (missing @)
- Test SQL injection in email field
- Verify XSS prevention in email input

### Password Validation
- Test minimum password length
- Test maximum password length
- Test password complexity rules
- Check password visibility toggle

## Security Testing

### Authentication
- Verify CSRF token validation
- Test brute force protection
- Check session timeout handling
- Test secure cookie attributes

### Authorization
- Test role-based access control
- Verify permission escalation prevention
- Test API endpoint authorization
"""

    result = ingest_brain_content(sample_brain)
    print(result.summary())

    print("\n" + "=" * 40)
    print("\nSecurity-tagged chunks:")
    for chunk in result.get_by_tag("security"):
        print(f"  [{chunk.section_id}] {chunk.content[:60]}...")
