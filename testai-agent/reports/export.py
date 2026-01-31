"""
TestAI Agent - Report Export

Exports reports to various formats (HTML, PDF placeholder, JSON, Markdown).
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any
import json

from .visual_report import VisualReport


class ExportFormat(Enum):
    """Available export formats."""
    HTML = "html"
    JSON = "json"
    MARKDOWN = "markdown"


@dataclass
class ExportResult:
    """Result of an export operation."""
    success: bool
    format: ExportFormat
    file_path: Optional[str]
    file_size: int
    message: str


class ReportExporter:
    """
    Exports reports to various file formats.
    """

    def __init__(self, output_dir: str = "."):
        """Initialize the exporter."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(
        self,
        report: VisualReport,
        format: ExportFormat,
        filename: Optional[str] = None,
    ) -> ExportResult:
        """Export a report to the specified format."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_title = "".join(c for c in report.title if c.isalnum() or c in " -_").replace(" ", "_")
            filename = f"{safe_title}_{timestamp}"

        if format == ExportFormat.HTML:
            return self._export_html(report, filename)
        elif format == ExportFormat.JSON:
            return self._export_json(report, filename)
        elif format == ExportFormat.MARKDOWN:
            return self._export_markdown(report, filename)
        else:
            return ExportResult(
                success=False,
                format=format,
                file_path=None,
                file_size=0,
                message=f"Unsupported format: {format}",
            )

    def _export_html(self, report: VisualReport, filename: str) -> ExportResult:
        """Export as HTML file."""
        file_path = self.output_dir / f"{filename}.html"

        try:
            content = report.html_content
            file_path.write_text(content)

            return ExportResult(
                success=True,
                format=ExportFormat.HTML,
                file_path=str(file_path),
                file_size=len(content),
                message=f"HTML report exported to {file_path}",
            )
        except Exception as e:
            return ExportResult(
                success=False,
                format=ExportFormat.HTML,
                file_path=None,
                file_size=0,
                message=f"Failed to export HTML: {str(e)}",
            )

    def _export_json(self, report: VisualReport, filename: str) -> ExportResult:
        """Export as JSON file."""
        file_path = self.output_dir / f"{filename}.json"

        try:
            data = {
                "title": report.title,
                "subtitle": report.subtitle,
                "generated_at": report.generated_at.isoformat(),
                "theme": report.theme.value,
                "metadata": report.metadata,
                "sections": [
                    {
                        "title": s.title,
                        "priority": s.priority,
                        "has_chart": s.chart is not None,
                        "has_table": s.table_data is not None,
                    }
                    for s in report.sections
                ],
            }

            content = json.dumps(data, indent=2)
            file_path.write_text(content)

            return ExportResult(
                success=True,
                format=ExportFormat.JSON,
                file_path=str(file_path),
                file_size=len(content),
                message=f"JSON report exported to {file_path}",
            )
        except Exception as e:
            return ExportResult(
                success=False,
                format=ExportFormat.JSON,
                file_path=None,
                file_size=0,
                message=f"Failed to export JSON: {str(e)}",
            )

    def _export_markdown(self, report: VisualReport, filename: str) -> ExportResult:
        """Export as Markdown file."""
        file_path = self.output_dir / f"{filename}.md"

        try:
            lines = [
                f"# {report.title}",
                "",
                f"*{report.subtitle}*",
                "",
                f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "---",
                "",
            ]

            for section in sorted(report.sections, key=lambda s: s.priority):
                lines.extend([
                    f"## {section.title}",
                    "",
                ])

                # Extract text content (strip HTML tags - simple approach)
                import re
                text_content = re.sub(r'<[^>]+>', '', section.content)
                text_content = re.sub(r'\s+', ' ', text_content).strip()
                if text_content:
                    lines.append(text_content)
                    lines.append("")

                # Add table if present
                if section.table_data:
                    headers = list(section.table_data.keys())
                    lines.append("| " + " | ".join(headers) + " |")
                    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

                    num_rows = len(list(section.table_data.values())[0]) if section.table_data else 0
                    for i in range(min(num_rows, 20)):  # Limit rows
                        row = [str(section.table_data[h][i]) for h in headers]
                        lines.append("| " + " | ".join(row) + " |")

                    if num_rows > 20:
                        lines.append(f"*... and {num_rows - 20} more rows*")
                    lines.append("")

                lines.append("")

            lines.extend([
                "---",
                "",
                f"*Report generated by TestAI Agent*",
            ])

            content = "\n".join(lines)
            file_path.write_text(content)

            return ExportResult(
                success=True,
                format=ExportFormat.MARKDOWN,
                file_path=str(file_path),
                file_size=len(content),
                message=f"Markdown report exported to {file_path}",
            )
        except Exception as e:
            return ExportResult(
                success=False,
                format=ExportFormat.MARKDOWN,
                file_path=None,
                file_size=0,
                message=f"Failed to export Markdown: {str(e)}",
            )

    def export_all_formats(
        self,
        report: VisualReport,
        base_filename: Optional[str] = None,
    ) -> Dict[ExportFormat, ExportResult]:
        """Export to all available formats."""
        results = {}
        for format in ExportFormat:
            results[format] = self.export(report, format, base_filename)
        return results


def export_report(
    report: VisualReport,
    format: ExportFormat = ExportFormat.HTML,
    output_dir: str = ".",
    filename: Optional[str] = None,
) -> ExportResult:
    """Convenience function to export a report."""
    exporter = ReportExporter(output_dir)
    return exporter.export(report, format, filename)
