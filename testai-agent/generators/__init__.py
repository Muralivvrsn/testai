"""
TestAI Agent - Generators Module

Test generation with brain integration.
Produces tests that surpass human QA.
"""

from .test_generator import TestGenerator, TestCase, TestSuite, GenerationResult, TestCategory, Priority
from .prompts import (
    EXPERT_QA_SYSTEM_PROMPT,
    get_feature_prompt,
    get_template_tests,
    HUMAN_QUALITY_TEMPLATES,
)
from .report_generator import (
    ReportGenerator,
    ReportFormat,
    TestReport,
    ReportMetadata,
    generate_report,
)
from .executive_report import (
    ExecutiveReportGenerator,
    ExecutiveReport,
    AudienceType,
    RiskLevel,
    RiskAssessment,
    CoverageMetrics,
    generate_executive_report,
)
from .cited_generator import (
    CitedTestGenerator,
    CitedTestCase,
    CitedTestPlan,
    Citation,
    TestCategory as CitedTestCategory,
    TestPriority as CitedTestPriority,
    create_login_generator,
)
from .executive_summary import (
    ExecutiveSummaryGenerator,
    ExecutiveSummary,
    StakeholderType,
    ShipDecision,
    RiskItem,
    CoverageMetrics as SummaryCoverageMetrics,
    create_executive_summary,
)
from .test_data import (
    TestDataGenerator,
    TestDataSet,
    TestDataItem,
    DataCategory,
    InputType,
    create_test_data_generator,
)

__all__ = [
    # Test Generator
    'TestGenerator',
    'TestCase',
    'TestSuite',
    'GenerationResult',
    'TestCategory',
    'Priority',
    # Prompts
    'EXPERT_QA_SYSTEM_PROMPT',
    'get_feature_prompt',
    'get_template_tests',
    'HUMAN_QUALITY_TEMPLATES',
    # Report Generator
    'ReportGenerator',
    'ReportFormat',
    'TestReport',
    'ReportMetadata',
    'generate_report',
    # Executive Reports
    'ExecutiveReportGenerator',
    'ExecutiveReport',
    'AudienceType',
    'RiskLevel',
    'RiskAssessment',
    'CoverageMetrics',
    'generate_executive_report',
    # Cited Generator
    'CitedTestGenerator',
    'CitedTestCase',
    'CitedTestPlan',
    'Citation',
    'CitedTestCategory',
    'CitedTestPriority',
    'create_login_generator',
    # Executive Summary
    'ExecutiveSummaryGenerator',
    'ExecutiveSummary',
    'StakeholderType',
    'ShipDecision',
    'RiskItem',
    'SummaryCoverageMetrics',
    'create_executive_summary',
    # Test Data Generator
    'TestDataGenerator',
    'TestDataSet',
    'TestDataItem',
    'DataCategory',
    'InputType',
    'create_test_data_generator',
]
