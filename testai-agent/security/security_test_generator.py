"""
TestAI Agent - Security Test Generator

Generates comprehensive security test cases from vulnerability scans.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import uuid

from .vulnerability_scanner import (
    VulnerabilityScanner,
    VulnerabilityType,
    SeverityLevel,
    Vulnerability,
    ScanResult,
)


class SecurityCategory(Enum):
    """Categories of security tests."""
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SESSION = "session"
    XSS = "xss"
    CSRF = "csrf"
    DATA_PROTECTION = "data_protection"
    RATE_LIMITING = "rate_limiting"
    CRYPTOGRAPHY = "cryptography"
    INPUT_VALIDATION = "input_validation"


@dataclass
class SecurityTestCase:
    """A security-focused test case."""
    id: str
    title: str
    description: str
    category: SecurityCategory
    priority: str
    vulnerability_id: str
    owasp_reference: str
    cwe_id: Optional[str]
    preconditions: List[str] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    test_data: List[str] = field(default_factory=list)
    expected_result: str = ""
    remediation_verification: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class SecurityTestSuite:
    """A complete security test suite."""
    name: str
    page_type: str
    generated_at: datetime
    test_cases: List[SecurityTestCase] = field(default_factory=list)
    total_tests: int = 0
    coverage: Dict[str, int] = field(default_factory=dict)


class SecurityTestGenerator:
    """
    Generates security test cases from vulnerability scan results.
    """

    # Test data payloads by vulnerability type
    TEST_PAYLOADS = {
        VulnerabilityType.INJECTION: [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "1; SELECT * FROM users",
            "' OR 1=1--",
            "admin'--",
            "') OR ('1'='1",
            "'; WAITFOR DELAY '0:0:5'--",
        ],
        VulnerabilityType.XSS: [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert(document.cookie)</script>",
            "<body onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>",
        ],
        VulnerabilityType.CSRF: [
            "Missing CSRF token",
            "Invalid CSRF token",
            "Expired CSRF token",
            "CSRF token from different session",
        ],
    }

    # Step templates by category
    STEP_TEMPLATES = {
        SecurityCategory.INJECTION: [
            "Navigate to {page} form",
            "Enter injection payload: {payload}",
            "Submit the form",
            "Verify application handles malicious input safely",
            "Check response for database errors or unexpected behavior",
        ],
        SecurityCategory.XSS: [
            "Navigate to {page} with input fields",
            "Enter XSS payload: {payload}",
            "Submit or trigger the input",
            "Verify payload is not executed",
            "Check that content is properly escaped in response",
        ],
        SecurityCategory.AUTHENTICATION: [
            "Navigate to {page}",
            "Attempt authentication with test credentials",
            "Verify response behavior",
            "Check for proper error handling",
            "Verify no sensitive information is leaked",
        ],
        SecurityCategory.AUTHORIZATION: [
            "Authenticate as low-privilege user",
            "Attempt to access {resource}",
            "Verify access is properly denied",
            "Check response code is 403 or appropriate",
        ],
        SecurityCategory.SESSION: [
            "Record current session ID",
            "Perform authentication",
            "Verify session ID has changed",
            "Check session cookie attributes (HttpOnly, Secure, SameSite)",
        ],
        SecurityCategory.CSRF: [
            "Identify form action endpoint",
            "Attempt submission without CSRF token",
            "Verify request is rejected",
            "Attempt submission with invalid token",
            "Verify proper token validation",
        ],
        SecurityCategory.RATE_LIMITING: [
            "Send multiple requests in quick succession",
            "Verify rate limiting kicks in after threshold",
            "Check for appropriate rate limit response (429)",
            "Verify lockout/cooldown period",
        ],
        SecurityCategory.DATA_PROTECTION: [
            "Capture network traffic during submission",
            "Verify sensitive data is encrypted in transit",
            "Check that sensitive data is not in logs",
            "Verify sensitive data is not in URL parameters",
        ],
    }

    def __init__(self, scanner: Optional[VulnerabilityScanner] = None):
        """Initialize the generator."""
        self.scanner = scanner or VulnerabilityScanner()
        self._test_count = 0

    def generate_from_scan(
        self,
        scan_result: ScanResult,
        include_payloads: bool = True,
    ) -> SecurityTestSuite:
        """Generate test cases from a vulnerability scan result."""
        test_cases = []

        for vuln in scan_result.vulnerabilities:
            # Generate test case for this vulnerability
            test_case = self._generate_test_case(vuln, scan_result.page_type, include_payloads)
            test_cases.append(test_case)

        # Calculate coverage
        coverage = {}
        for tc in test_cases:
            cat = tc.category.value
            coverage[cat] = coverage.get(cat, 0) + 1

        return SecurityTestSuite(
            name=f"Security Tests: {scan_result.feature}",
            page_type=scan_result.page_type,
            generated_at=datetime.now(),
            test_cases=test_cases,
            total_tests=len(test_cases),
            coverage=coverage,
        )

    def generate_for_page(
        self,
        page_type: str,
        feature: str = "Feature",
        include_payloads: bool = True,
    ) -> SecurityTestSuite:
        """Generate security tests for a page type."""
        # Scan for vulnerabilities
        scan_result = self.scanner.scan(page_type, feature)

        # Generate tests from scan
        return self.generate_from_scan(scan_result, include_payloads)

    def _generate_test_case(
        self,
        vuln: Vulnerability,
        page_type: str,
        include_payloads: bool,
    ) -> SecurityTestCase:
        """Generate a test case for a specific vulnerability."""
        self._test_count += 1

        # Map vulnerability type to security category
        category = self._map_to_category(vuln.vulnerability_type)

        # Determine priority from severity
        priority = self._severity_to_priority(vuln.severity)

        # Generate steps
        steps = self._generate_steps(category, page_type, vuln)

        # Get test data/payloads
        test_data = []
        if include_payloads:
            test_data = self._get_test_data(vuln.vulnerability_type)

        # Generate expected result
        expected = self._generate_expected_result(category, vuln)

        return SecurityTestCase(
            id=f"SEC-{self._test_count:04d}",
            title=f"Security: {vuln.title}",
            description=vuln.description,
            category=category,
            priority=priority,
            vulnerability_id=vuln.id,
            owasp_reference=vuln.owasp_reference,
            cwe_id=vuln.cwe_id,
            preconditions=self._get_preconditions(category, page_type),
            steps=steps,
            test_data=test_data,
            expected_result=expected,
            remediation_verification=vuln.remediation,
            tags=self._generate_tags(vuln, category),
        )

    def _map_to_category(self, vuln_type: VulnerabilityType) -> SecurityCategory:
        """Map vulnerability type to security category."""
        mapping = {
            VulnerabilityType.INJECTION: SecurityCategory.INJECTION,
            VulnerabilityType.XSS: SecurityCategory.XSS,
            VulnerabilityType.CSRF: SecurityCategory.CSRF,
            VulnerabilityType.SESSION_FIXATION: SecurityCategory.SESSION,
            VulnerabilityType.BRUTE_FORCE: SecurityCategory.RATE_LIMITING,
            VulnerabilityType.RATE_LIMITING: SecurityCategory.RATE_LIMITING,
            VulnerabilityType.AUTH_FAILURES: SecurityCategory.AUTHENTICATION,
            VulnerabilityType.BROKEN_ACCESS_CONTROL: SecurityCategory.AUTHORIZATION,
            VulnerabilityType.SENSITIVE_DATA_EXPOSURE: SecurityCategory.DATA_PROTECTION,
            VulnerabilityType.CRYPTOGRAPHIC_FAILURES: SecurityCategory.CRYPTOGRAPHY,
        }
        return mapping.get(vuln_type, SecurityCategory.INPUT_VALIDATION)

    def _severity_to_priority(self, severity: SeverityLevel) -> str:
        """Map severity to priority."""
        mapping = {
            SeverityLevel.CRITICAL: "critical",
            SeverityLevel.HIGH: "high",
            SeverityLevel.MEDIUM: "medium",
            SeverityLevel.LOW: "low",
            SeverityLevel.INFO: "low",
        }
        return mapping.get(severity, "medium")

    def _generate_steps(
        self,
        category: SecurityCategory,
        page_type: str,
        vuln: Vulnerability,
    ) -> List[str]:
        """Generate test steps."""
        templates = self.STEP_TEMPLATES.get(category, [])

        steps = []
        for template in templates:
            step = template.format(
                page=page_type,
                payload="{payload}",  # Placeholder
                resource=vuln.affected_component,
            )
            steps.append(step)

        # Add vulnerability-specific step
        steps.append(f"Verify: {vuln.test_required}")

        return steps

    def _get_test_data(self, vuln_type: VulnerabilityType) -> List[str]:
        """Get test data/payloads for vulnerability type."""
        return self.TEST_PAYLOADS.get(vuln_type, [])

    def _get_preconditions(
        self,
        category: SecurityCategory,
        page_type: str,
    ) -> List[str]:
        """Get preconditions for the test."""
        preconditions = ["Application is accessible", "Test environment is configured"]

        if category in [SecurityCategory.AUTHORIZATION, SecurityCategory.SESSION]:
            preconditions.append("Test user accounts are available")

        if page_type == "checkout":
            preconditions.append("Test payment credentials available")

        if category == SecurityCategory.RATE_LIMITING:
            preconditions.append("Rate limit thresholds are known")

        return preconditions

    def _generate_expected_result(
        self,
        category: SecurityCategory,
        vuln: Vulnerability,
    ) -> str:
        """Generate expected result description."""
        expected_results = {
            SecurityCategory.INJECTION: "Application rejects malicious input, no SQL errors or unexpected data returned",
            SecurityCategory.XSS: "XSS payload is properly escaped, no script execution occurs",
            SecurityCategory.CSRF: "Request without valid CSRF token is rejected with appropriate error",
            SecurityCategory.AUTHENTICATION: "Authentication behaves securely, no information leakage",
            SecurityCategory.AUTHORIZATION: "Unauthorized access is denied with 403 status",
            SecurityCategory.SESSION: "Session is properly managed, ID regenerated after auth",
            SecurityCategory.RATE_LIMITING: "Rate limiting activates after threshold, returns 429 status",
            SecurityCategory.DATA_PROTECTION: "Sensitive data is encrypted and not exposed",
            SecurityCategory.CRYPTOGRAPHY: "Proper encryption is used for sensitive data",
            SecurityCategory.INPUT_VALIDATION: "Invalid input is properly rejected with clear error",
        }
        return expected_results.get(category, "Security controls function as expected")

    def _generate_tags(
        self,
        vuln: Vulnerability,
        category: SecurityCategory,
    ) -> List[str]:
        """Generate tags for the test case."""
        tags = [
            "security",
            category.value,
            vuln.vulnerability_type.value,
            vuln.severity.value,
        ]

        if vuln.cwe_id:
            tags.append(vuln.cwe_id)

        # Add OWASP tag
        if vuln.owasp_reference:
            owasp_id = vuln.owasp_reference.split(":")[0] if ":" in vuln.owasp_reference else vuln.owasp_reference
            tags.append(owasp_id)

        return tags

    def format_test_suite(self, suite: SecurityTestSuite) -> str:
        """Format test suite as readable output."""
        lines = [
            "=" * 70,
            f"  SECURITY TEST SUITE: {suite.name}",
            "=" * 70,
            "",
            f"  Page Type: {suite.page_type}",
            f"  Generated: {suite.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Total Tests: {suite.total_tests}",
            "",
            "-" * 70,
            "  COVERAGE",
            "-" * 70,
        ]

        for cat, count in sorted(suite.coverage.items()):
            lines.append(f"  {cat:20} {count} test(s)")

        lines.append("")

        # List test cases
        for i, tc in enumerate(suite.test_cases, 1):
            priority_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            icon = priority_icon.get(tc.priority, "⚪")

            lines.extend([
                "-" * 70,
                f"  {icon} [{tc.id}] {tc.title}",
                "-" * 70,
                f"  Category: {tc.category.value}",
                f"  Priority: {tc.priority}",
                f"  OWASP: {tc.owasp_reference}",
                f"  CWE: {tc.cwe_id or 'N/A'}",
                "",
                "  Steps:",
            ])

            for j, step in enumerate(tc.steps, 1):
                lines.append(f"    {j}. {step}")

            lines.extend([
                "",
                f"  Expected: {tc.expected_result}",
                "",
            ])

            if tc.test_data:
                lines.append("  Test Payloads:")
                for payload in tc.test_data[:3]:  # Show first 3
                    lines.append(f"    - {payload[:50]}...")
                if len(tc.test_data) > 3:
                    lines.append(f"    ... and {len(tc.test_data) - 3} more")
                lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)

    def to_dict(self, suite: SecurityTestSuite) -> Dict[str, Any]:
        """Convert test suite to dictionary format."""
        return {
            "name": suite.name,
            "page_type": suite.page_type,
            "generated_at": suite.generated_at.isoformat(),
            "total_tests": suite.total_tests,
            "coverage": suite.coverage,
            "test_cases": [
                {
                    "id": tc.id,
                    "title": tc.title,
                    "description": tc.description,
                    "category": tc.category.value,
                    "priority": tc.priority,
                    "vulnerability_id": tc.vulnerability_id,
                    "owasp_reference": tc.owasp_reference,
                    "cwe_id": tc.cwe_id,
                    "preconditions": tc.preconditions,
                    "steps": tc.steps,
                    "test_data": tc.test_data,
                    "expected_result": tc.expected_result,
                    "tags": tc.tags,
                }
                for tc in suite.test_cases
            ],
        }


def create_security_generator(
    scanner: Optional[VulnerabilityScanner] = None,
) -> SecurityTestGenerator:
    """Create a security test generator instance."""
    return SecurityTestGenerator(scanner)
