"""
TestAI Agent - Documentation Module

Generates comprehensive test documentation including
test plans, coverage reports, and execution summaries.
"""

from .generator import (
    DocGenerator,
    DocumentType,
    DocumentFormat,
    TestDocument,
    create_doc_generator,
)

from .test_plan import (
    TestPlanGenerator,
    TestPlan,
    TestCase,
    create_test_plan_generator,
)

from .coverage_report import (
    CoverageReportGenerator,
    CoverageReport,
    FeatureCoverage,
    create_coverage_report_generator,
)

__all__ = [
    # Generator
    "DocGenerator",
    "DocumentType",
    "DocumentFormat",
    "TestDocument",
    "create_doc_generator",
    # Test Plan
    "TestPlanGenerator",
    "TestPlan",
    "TestCase",
    "create_test_plan_generator",
    # Coverage Report
    "CoverageReportGenerator",
    "CoverageReport",
    "FeatureCoverage",
    "create_coverage_report_generator",
]
