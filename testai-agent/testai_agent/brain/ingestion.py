"""
TestAI Agent - Knowledge Ingestion

Parses QA_BRAIN.md with section-level tagging for precise RAG retrieval.
Every piece of knowledge gets a section ID for citation.

Markdown Format Expected:
    ## 1. Input Validation
    ## 2. Security Testing
    ## 2.1 SQL Injection
    ## 7.1 Email Validation
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class SectionType(Enum):
    """Types of knowledge sections."""
    RULES = "rules"
    EXAMPLES = "examples"
    CHECKLISTS = "checklists"
    EDGE_CASES = "edge_cases"
    SECURITY = "security"
    VALIDATION = "validation"


@dataclass
class ParsedSection:
    """A parsed section from the knowledge base."""
    id: str
    title: str
    content: str
    section_type: SectionType
    subsections: List['ParsedSection']
    depth: int

    @property
    def citation(self) -> str:
        return f"Section {self.id} - {self.title}"

    def get_all_content(self) -> str:
        """Get content including subsections."""
        all_content = self.content
        for sub in self.subsections:
            all_content += f"\n\n### {sub.title}\n{sub.get_all_content()}"
        return all_content


class KnowledgeParser:
    """
    Parses QA_BRAIN.md into structured sections.

    Features:
    - Section ID extraction (1, 2.1, 7.1.2, etc.)
    - Section type detection (rules, examples, etc.)
    - Hierarchical structure preservation
    - Citation-ready output
    """

    # Patterns for section headers
    SECTION_PATTERNS = [
        # ## 1. Title or ## 1.1 Title or ## 1.1.1 Title
        (r'^##\s+(\d+(?:\.\d+)*)\.\s*(.+)$', 2),
        # ### Subsection Title (for unnumbered subsections)
        (r'^###\s+(.+)$', 3),
    ]

    def __init__(self):
        self.sections: List[ParsedSection] = []
        self.section_map: Dict[str, ParsedSection] = {}

    def parse(self, file_path: str) -> List[ParsedSection]:
        """
        Parse a markdown knowledge base.

        Returns list of top-level sections with subsections nested.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Knowledge base not found: {path}")

        content = path.read_text(encoding='utf-8')
        return self.parse_content(content)

    def parse_content(self, content: str) -> List[ParsedSection]:
        """Parse markdown content string."""
        self.sections = []
        self.section_map = {}

        lines = content.split('\n')
        current_section = None
        current_content = []
        section_stack = []

        for line in lines:
            # Check for section header
            section_match = self._match_section_header(line)

            if section_match:
                # Save previous section content
                if current_section:
                    current_section.content = '\n'.join(current_content).strip()

                section_id, title, depth = section_match

                # Create new section
                section_type = self._detect_section_type(title)
                new_section = ParsedSection(
                    id=section_id,
                    title=title,
                    content="",
                    section_type=section_type,
                    subsections=[],
                    depth=depth
                )

                # Place in hierarchy
                self._place_in_hierarchy(new_section, section_stack)

                self.section_map[section_id] = new_section
                current_section = new_section
                current_content = []

            else:
                current_content.append(line)

        # Save last section
        if current_section:
            current_section.content = '\n'.join(current_content).strip()

        return self.sections

    def get_section(self, section_id: str) -> Optional[ParsedSection]:
        """Get a section by ID."""
        return self.section_map.get(section_id)

    def get_all_sections_flat(self) -> List[ParsedSection]:
        """Get all sections flattened."""
        result = []
        for section in self.sections:
            result.extend(self._flatten_section(section))
        return result

    def get_sections_by_type(self, section_type: SectionType) -> List[ParsedSection]:
        """Get all sections of a specific type."""
        all_sections = self.get_all_sections_flat()
        return [s for s in all_sections if s.section_type == section_type]

    def generate_index(self) -> str:
        """Generate a table of contents."""
        lines = ["# Knowledge Base Index\n"]

        for section in self.sections:
            lines.append(self._format_index_entry(section, 0))

        return '\n'.join(lines)

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _match_section_header(self, line: str) -> Optional[tuple]:
        """Match a section header line."""
        line = line.strip()

        # Match numbered sections: ## 1. Title or ## 1.1 Title or ## 1.1. Title
        # The trailing dot after the number is optional
        match = re.match(r'^##\s+(\d+(?:\.\d+)*)\.?\s+(.+)$', line)
        if match:
            section_id = match.group(1)
            title = match.group(2).strip()
            depth = section_id.count('.') + 1
            return (section_id, title, depth)

        return None

    def _detect_section_type(self, title: str) -> SectionType:
        """Detect section type from title."""
        title_lower = title.lower()

        if 'security' in title_lower or 'attack' in title_lower:
            return SectionType.SECURITY
        if 'validation' in title_lower or 'input' in title_lower:
            return SectionType.VALIDATION
        if 'example' in title_lower:
            return SectionType.EXAMPLES
        if 'checklist' in title_lower:
            return SectionType.CHECKLISTS
        if 'edge' in title_lower or 'boundary' in title_lower:
            return SectionType.EDGE_CASES

        return SectionType.RULES

    def _place_in_hierarchy(self, section: ParsedSection, stack: List[ParsedSection]):
        """Place section in the correct hierarchy level."""
        # Remove sections from stack that are same or deeper level
        while stack and stack[-1].depth >= section.depth:
            stack.pop()

        if stack:
            # Add as subsection to parent
            stack[-1].subsections.append(section)
        else:
            # Top-level section
            self.sections.append(section)

        stack.append(section)

    def _flatten_section(self, section: ParsedSection) -> List[ParsedSection]:
        """Flatten a section and its subsections."""
        result = [section]
        for sub in section.subsections:
            result.extend(self._flatten_section(sub))
        return result

    def _format_index_entry(self, section: ParsedSection, indent: int) -> str:
        """Format a section for the index."""
        prefix = "  " * indent
        entry = f"{prefix}- **{section.id}.** {section.title} [{section.section_type.value}]"

        lines = [entry]
        for sub in section.subsections:
            lines.append(self._format_index_entry(sub, indent + 1))

        return '\n'.join(lines)


def parse_knowledge_base(file_path: str) -> List[ParsedSection]:
    """Convenience function to parse a knowledge base."""
    parser = KnowledgeParser()
    return parser.parse(file_path)


def get_section_citation(section: ParsedSection) -> str:
    """Get a formatted citation for a section."""
    return f"Source: Section {section.id} - {section.title}"
