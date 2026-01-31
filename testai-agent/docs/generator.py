"""
TestAI Agent - Documentation Generator

Generates various documentation formats for tests
including Markdown, HTML, and JSON.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import json


class DocumentType(Enum):
    """Types of documentation."""
    TEST_PLAN = "test_plan"
    TEST_CASE = "test_case"
    EXECUTION_REPORT = "execution_report"
    COVERAGE_REPORT = "coverage_report"
    RELEASE_NOTES = "release_notes"
    API_DOCS = "api_docs"


class DocumentFormat(Enum):
    """Output formats for documentation."""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    TEXT = "text"


@dataclass
class TestDocument:
    """A generated test document."""
    doc_id: str
    doc_type: DocumentType
    title: str
    content: str
    format: DocumentFormat
    metadata: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.now)
    version: str = "1.0"


class DocGenerator:
    """
    Generates test documentation.

    Features:
    - Multiple format support
    - Template-based generation
    - Metadata inclusion
    - Version tracking
    """

    def __init__(self):
        """Initialize the documentation generator."""
        self._doc_counter = 0
        self._documents: Dict[str, TestDocument] = {}

    def generate(
        self,
        doc_type: DocumentType,
        data: Dict[str, Any],
        format: DocumentFormat = DocumentFormat.MARKDOWN,
        title: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TestDocument:
        """Generate a document."""
        self._doc_counter += 1

        content = self._generate_content(doc_type, data, format)

        doc = TestDocument(
            doc_id=f"DOC-{self._doc_counter:05d}",
            doc_type=doc_type,
            title=title or self._generate_title(doc_type),
            content=content,
            format=format,
            metadata=metadata or {},
        )

        self._documents[doc.doc_id] = doc
        return doc

    def _generate_content(
        self,
        doc_type: DocumentType,
        data: Dict[str, Any],
        format: DocumentFormat,
    ) -> str:
        """Generate content based on type and format."""
        # Get template function
        generators = {
            DocumentType.TEST_PLAN: self._gen_test_plan,
            DocumentType.TEST_CASE: self._gen_test_case,
            DocumentType.EXECUTION_REPORT: self._gen_execution_report,
            DocumentType.COVERAGE_REPORT: self._gen_coverage_report,
            DocumentType.RELEASE_NOTES: self._gen_release_notes,
            DocumentType.API_DOCS: self._gen_api_docs,
        }

        generator = generators.get(doc_type, self._gen_generic)
        return generator(data, format)

    def _generate_title(self, doc_type: DocumentType) -> str:
        """Generate default title for document type."""
        titles = {
            DocumentType.TEST_PLAN: "Test Plan",
            DocumentType.TEST_CASE: "Test Case Documentation",
            DocumentType.EXECUTION_REPORT: "Test Execution Report",
            DocumentType.COVERAGE_REPORT: "Test Coverage Report",
            DocumentType.RELEASE_NOTES: "Release Notes",
            DocumentType.API_DOCS: "API Documentation",
        }
        return titles.get(doc_type, "Documentation")

    def _gen_test_plan(
        self,
        data: Dict[str, Any],
        format: DocumentFormat,
    ) -> str:
        """Generate test plan document."""
        if format == DocumentFormat.MARKDOWN:
            lines = [
                f"# {data.get('title', 'Test Plan')}",
                "",
                f"**Version:** {data.get('version', '1.0')}",
                f"**Created:** {datetime.now().strftime('%Y-%m-%d')}",
                "",
                "## Overview",
                "",
                data.get('overview', 'Test plan overview.'),
                "",
                "## Scope",
                "",
            ]

            for item in data.get('scope', []):
                lines.append(f"- {item}")

            lines.extend([
                "",
                "## Test Cases",
                "",
            ])

            for tc in data.get('test_cases', []):
                lines.extend([
                    f"### {tc.get('id', 'TC-XXX')}: {tc.get('name', 'Test')}",
                    "",
                    f"**Priority:** {tc.get('priority', 'Medium')}",
                    "",
                    tc.get('description', ''),
                    "",
                ])

            return "\n".join(lines)

        elif format == DocumentFormat.HTML:
            return self._wrap_html(self._gen_test_plan(data, DocumentFormat.MARKDOWN))

        elif format == DocumentFormat.JSON:
            return json.dumps(data, indent=2, default=str)

        return str(data)

    def _gen_test_case(
        self,
        data: Dict[str, Any],
        format: DocumentFormat,
    ) -> str:
        """Generate test case document."""
        if format == DocumentFormat.MARKDOWN:
            lines = [
                f"# Test Case: {data.get('id', 'TC-XXX')}",
                "",
                f"**Name:** {data.get('name', 'Test Case')}",
                f"**Priority:** {data.get('priority', 'Medium')}",
                f"**Status:** {data.get('status', 'Draft')}",
                "",
                "## Description",
                "",
                data.get('description', 'Test case description.'),
                "",
                "## Preconditions",
                "",
            ]

            for pre in data.get('preconditions', []):
                lines.append(f"- {pre}")

            lines.extend([
                "",
                "## Steps",
                "",
            ])

            for i, step in enumerate(data.get('steps', []), 1):
                lines.append(f"{i}. {step}")

            lines.extend([
                "",
                "## Expected Results",
                "",
            ])

            for result in data.get('expected_results', []):
                lines.append(f"- {result}")

            return "\n".join(lines)

        elif format == DocumentFormat.JSON:
            return json.dumps(data, indent=2, default=str)

        return str(data)

    def _gen_execution_report(
        self,
        data: Dict[str, Any],
        format: DocumentFormat,
    ) -> str:
        """Generate execution report."""
        if format == DocumentFormat.MARKDOWN:
            lines = [
                "# Test Execution Report",
                "",
                f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                f"**Environment:** {data.get('environment', 'Unknown')}",
                "",
                "## Summary",
                "",
                f"| Metric | Value |",
                f"|--------|-------|",
                f"| Total Tests | {data.get('total', 0)} |",
                f"| Passed | {data.get('passed', 0)} |",
                f"| Failed | {data.get('failed', 0)} |",
                f"| Skipped | {data.get('skipped', 0)} |",
                f"| Duration | {data.get('duration_ms', 0)}ms |",
                "",
            ]

            if data.get('failures'):
                lines.extend([
                    "## Failures",
                    "",
                ])
                for failure in data.get('failures', []):
                    lines.extend([
                        f"### {failure.get('test_id', 'Unknown')}",
                        "",
                        f"**Error:** {failure.get('error', 'Unknown error')}",
                        "",
                    ])

            return "\n".join(lines)

        elif format == DocumentFormat.JSON:
            return json.dumps(data, indent=2, default=str)

        return str(data)

    def _gen_coverage_report(
        self,
        data: Dict[str, Any],
        format: DocumentFormat,
    ) -> str:
        """Generate coverage report."""
        if format == DocumentFormat.MARKDOWN:
            lines = [
                "# Test Coverage Report",
                "",
                f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                "",
                "## Overall Coverage",
                "",
                f"**Coverage:** {data.get('coverage_percent', 0):.1f}%",
                "",
                "## Features",
                "",
            ]

            for feature in data.get('features', []):
                status = "✅" if feature.get('covered') else "❌"
                lines.append(f"- {status} {feature.get('name', 'Unknown')}")

            if data.get('gaps'):
                lines.extend([
                    "",
                    "## Coverage Gaps",
                    "",
                ])
                for gap in data.get('gaps', []):
                    lines.append(f"- {gap}")

            return "\n".join(lines)

        elif format == DocumentFormat.JSON:
            return json.dumps(data, indent=2, default=str)

        return str(data)

    def _gen_release_notes(
        self,
        data: Dict[str, Any],
        format: DocumentFormat,
    ) -> str:
        """Generate release notes."""
        if format == DocumentFormat.MARKDOWN:
            lines = [
                f"# Release Notes - {data.get('version', '1.0')}",
                "",
                f"**Date:** {data.get('date', datetime.now().strftime('%Y-%m-%d'))}",
                "",
                "## Changes",
                "",
            ]

            for change in data.get('changes', []):
                lines.append(f"- {change}")

            if data.get('bug_fixes'):
                lines.extend([
                    "",
                    "## Bug Fixes",
                    "",
                ])
                for fix in data.get('bug_fixes', []):
                    lines.append(f"- {fix}")

            if data.get('known_issues'):
                lines.extend([
                    "",
                    "## Known Issues",
                    "",
                ])
                for issue in data.get('known_issues', []):
                    lines.append(f"- {issue}")

            return "\n".join(lines)

        elif format == DocumentFormat.JSON:
            return json.dumps(data, indent=2, default=str)

        return str(data)

    def _gen_api_docs(
        self,
        data: Dict[str, Any],
        format: DocumentFormat,
    ) -> str:
        """Generate API documentation."""
        if format == DocumentFormat.MARKDOWN:
            lines = [
                f"# {data.get('title', 'API Documentation')}",
                "",
                data.get('description', ''),
                "",
            ]

            for endpoint in data.get('endpoints', []):
                lines.extend([
                    f"## {endpoint.get('method', 'GET')} {endpoint.get('path', '/')}",
                    "",
                    endpoint.get('description', ''),
                    "",
                    "**Parameters:**",
                    "",
                ])

                for param in endpoint.get('parameters', []):
                    lines.append(f"- `{param.get('name')}`: {param.get('description', '')}")

                lines.append("")

            return "\n".join(lines)

        elif format == DocumentFormat.JSON:
            return json.dumps(data, indent=2, default=str)

        return str(data)

    def _gen_generic(
        self,
        data: Dict[str, Any],
        format: DocumentFormat,
    ) -> str:
        """Generate generic document."""
        if format == DocumentFormat.JSON:
            return json.dumps(data, indent=2, default=str)
        return str(data)

    def _wrap_html(self, markdown_content: str) -> str:
        """Wrap markdown content in HTML."""
        # Simple HTML conversion
        html = markdown_content
        html = html.replace("# ", "<h1>").replace("\n\n", "</h1>\n\n")
        html = html.replace("## ", "<h2>").replace("\n\n", "</h2>\n\n")
        html = html.replace("### ", "<h3>").replace("\n\n", "</h3>\n\n")
        html = html.replace("- ", "<li>").replace("\n", "</li>\n")

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Test Documentation</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #555; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    </style>
</head>
<body>
{html}
</body>
</html>"""

    def get_document(self, doc_id: str) -> Optional[TestDocument]:
        """Get a document by ID."""
        return self._documents.get(doc_id)

    def list_documents(
        self,
        doc_type: Optional[DocumentType] = None,
    ) -> List[TestDocument]:
        """List all documents."""
        docs = list(self._documents.values())

        if doc_type:
            docs = [d for d in docs if d.doc_type == doc_type]

        return docs


def create_doc_generator() -> DocGenerator:
    """Create a documentation generator instance."""
    return DocGenerator()
