"""
TestAI Agent - Vulnerability Scanner

Core vulnerability detection engine with OWASP
coverage and risk-based prioritization.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import uuid
import re


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels (CVSS-aligned)."""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9
    INFO = "info"          # Informational


class VulnerabilityCategory(Enum):
    """OWASP Top 10 2021 categories."""
    BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    INJECTION = "A03:2021-Injection"
    INSECURE_DESIGN = "A04:2021-Insecure Design"
    SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    DATA_INTEGRITY_FAILURES = "A08:2021-Software and Data Integrity Failures"
    LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    SSRF = "A10:2021-Server-Side Request Forgery"
    XSS = "XSS"  # Cross-Site Scripting (legacy but common)
    CSRF = "CSRF"  # Cross-Site Request Forgery


@dataclass
class Vulnerability:
    """A detected vulnerability."""
    vuln_id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    category: VulnerabilityCategory
    location: str
    evidence: str
    remediation: str
    cvss_score: float = 0.0
    cwe_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Result of a vulnerability scan."""
    scan_id: str
    target: str
    vulnerabilities: List[Vulnerability]
    scan_type: str
    started_at: datetime
    completed_at: datetime
    risk_score: float
    findings_by_severity: Dict[str, int]
    findings_by_category: Dict[str, int]
    metadata: Dict[str, Any] = field(default_factory=dict)


class VulnerabilityScanner:
    """
    Comprehensive vulnerability scanner.

    Features:
    - OWASP Top 10 coverage
    - Risk-based prioritization
    - Evidence collection
    - Remediation guidance
    """

    def __init__(
        self,
        scan_depth: str = "standard",
        timeout: int = 30000,
    ):
        """Initialize the scanner."""
        self._scan_depth = scan_depth
        self._timeout = timeout
        self._scans: List[ScanResult] = []
        self._vuln_counter = 0
        self._scan_counter = 0

        # Detection rules
        self._detection_rules = self._init_detection_rules()

    def _init_detection_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize vulnerability detection rules."""
        return {
            # Injection rules
            "sql_injection": {
                "category": VulnerabilityCategory.INJECTION,
                "severity": VulnerabilitySeverity.CRITICAL,
                "patterns": [
                    r"'.*OR.*'='",
                    r";\s*DROP\s+TABLE",
                    r"UNION\s+SELECT",
                    r"--\s*$",
                ],
                "indicators": ["error", "sql", "syntax", "query"],
                "cvss": 9.8,
                "cwe": "CWE-89",
            },
            "xss_reflected": {
                "category": VulnerabilityCategory.XSS,
                "severity": VulnerabilitySeverity.HIGH,
                "patterns": [
                    r"<script[^>]*>",
                    r"javascript:",
                    r"on\w+\s*=",
                    r"<img[^>]+onerror",
                ],
                "indicators": ["reflected", "user input"],
                "cvss": 7.5,
                "cwe": "CWE-79",
            },
            "xss_stored": {
                "category": VulnerabilityCategory.XSS,
                "severity": VulnerabilitySeverity.HIGH,
                "patterns": [
                    r"<script[^>]*>.*</script>",
                ],
                "indicators": ["stored", "persistent"],
                "cvss": 8.0,
                "cwe": "CWE-79",
            },
            "csrf_missing": {
                "category": VulnerabilityCategory.CSRF,
                "severity": VulnerabilitySeverity.MEDIUM,
                "patterns": [],
                "indicators": ["no csrf token", "missing token"],
                "cvss": 6.5,
                "cwe": "CWE-352",
            },
            "broken_auth": {
                "category": VulnerabilityCategory.AUTH_FAILURES,
                "severity": VulnerabilitySeverity.HIGH,
                "patterns": [
                    r"password\s*=",
                    r"auth.*bypass",
                ],
                "indicators": ["weak password", "no lockout", "session"],
                "cvss": 7.8,
                "cwe": "CWE-287",
            },
            "sensitive_data": {
                "category": VulnerabilityCategory.CRYPTOGRAPHIC_FAILURES,
                "severity": VulnerabilitySeverity.HIGH,
                "patterns": [
                    r"password.*=.*['\"]",
                    r"api[_-]?key.*=",
                    r"secret.*=",
                    r"-----BEGIN.*PRIVATE KEY-----",
                ],
                "indicators": ["exposed", "cleartext", "unencrypted"],
                "cvss": 7.5,
                "cwe": "CWE-200",
            },
            "security_misconfig": {
                "category": VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                "severity": VulnerabilitySeverity.MEDIUM,
                "patterns": [
                    r"X-Powered-By:",
                    r"Server:\s*Apache",
                    r"debug\s*=\s*[Tt]rue",
                ],
                "indicators": ["verbose error", "stack trace", "debug mode"],
                "cvss": 5.3,
                "cwe": "CWE-16",
            },
            "insecure_cookies": {
                "category": VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                "severity": VulnerabilitySeverity.MEDIUM,
                "patterns": [],
                "indicators": ["no httponly", "no secure flag", "samesite"],
                "cvss": 5.0,
                "cwe": "CWE-614",
            },
            "open_redirect": {
                "category": VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                "severity": VulnerabilitySeverity.MEDIUM,
                "patterns": [
                    r"redirect.*=.*http",
                    r"url.*=.*http",
                    r"next.*=.*http",
                ],
                "indicators": ["redirect", "external url"],
                "cvss": 6.1,
                "cwe": "CWE-601",
            },
            "ssrf": {
                "category": VulnerabilityCategory.SSRF,
                "severity": VulnerabilitySeverity.HIGH,
                "patterns": [
                    r"url=.*localhost",
                    r"url=.*127\.0\.0\.1",
                    r"url=.*169\.254",
                ],
                "indicators": ["internal", "metadata", "localhost"],
                "cvss": 8.0,
                "cwe": "CWE-918",
            },
            "path_traversal": {
                "category": VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                "severity": VulnerabilitySeverity.HIGH,
                "patterns": [
                    r"\.\./",
                    r"\.\.\\",
                    r"%2e%2e",
                ],
                "indicators": ["file", "path", "directory"],
                "cvss": 7.5,
                "cwe": "CWE-22",
            },
            "command_injection": {
                "category": VulnerabilityCategory.INJECTION,
                "severity": VulnerabilitySeverity.CRITICAL,
                "patterns": [
                    r";\s*\w+",
                    r"\|\s*\w+",
                    r"`[^`]+`",
                    r"\$\([^)]+\)",
                ],
                "indicators": ["command", "exec", "system", "shell"],
                "cvss": 9.8,
                "cwe": "CWE-78",
            },
        }

    def scan(
        self,
        target: str,
        scan_type: str = "full",
        elements: Optional[List[Dict[str, Any]]] = None,
        responses: Optional[List[Dict[str, Any]]] = None,
    ) -> ScanResult:
        """
        Scan a target for vulnerabilities.

        Args:
            target: Target URL or identifier
            scan_type: Type of scan (full, quick, passive)
            elements: DOM elements to analyze
            responses: HTTP responses to analyze
        """
        self._scan_counter += 1
        scan_id = f"SCAN-{self._scan_counter:05d}"
        started_at = datetime.now()

        vulnerabilities: List[Vulnerability] = []

        # Analyze elements if provided
        if elements:
            vulnerabilities.extend(self._scan_elements(elements, target))

        # Analyze responses if provided
        if responses:
            vulnerabilities.extend(self._scan_responses(responses, target))

        # Passive analysis (always run)
        vulnerabilities.extend(self._passive_scan(target))

        # Calculate statistics
        findings_by_severity = self._count_by_severity(vulnerabilities)
        findings_by_category = self._count_by_category(vulnerabilities)
        risk_score = self._calculate_risk_score(vulnerabilities)

        completed_at = datetime.now()

        result = ScanResult(
            scan_id=scan_id,
            target=target,
            vulnerabilities=vulnerabilities,
            scan_type=scan_type,
            started_at=started_at,
            completed_at=completed_at,
            risk_score=risk_score,
            findings_by_severity=findings_by_severity,
            findings_by_category=findings_by_category,
        )

        self._scans.append(result)
        return result

    def _scan_elements(
        self,
        elements: List[Dict[str, Any]],
        target: str,
    ) -> List[Vulnerability]:
        """Scan DOM elements for vulnerabilities."""
        vulnerabilities = []

        for element in elements:
            tag = element.get("tag", "").lower()
            attrs = element.get("attributes", {})
            text = element.get("text", "")

            # Check for inline event handlers (potential XSS vector)
            for attr, value in attrs.items():
                if attr.startswith("on") and value:
                    vuln = self._create_vulnerability(
                        rule_id="xss_reflected",
                        title="Inline Event Handler Detected",
                        description=f"Element has inline event handler '{attr}' which could be an XSS vector",
                        location=f"{target}#{element.get('selector', tag)}",
                        evidence=f"{attr}=\"{value[:100]}\"",
                        remediation="Use addEventListener instead of inline handlers",
                    )
                    vulnerabilities.append(vuln)

            # Check for forms without CSRF protection
            if tag == "form":
                action = attrs.get("action", "")
                method = attrs.get("method", "get").lower()

                if method == "post" and "csrf" not in str(element).lower():
                    vuln = self._create_vulnerability(
                        rule_id="csrf_missing",
                        title="Form Missing CSRF Token",
                        description="POST form does not appear to have CSRF protection",
                        location=f"{target}#{element.get('selector', 'form')}",
                        evidence=f"<form action='{action}' method='post'>",
                        remediation="Add CSRF token to all state-changing forms",
                    )
                    vulnerabilities.append(vuln)

            # Check for password inputs without autocomplete off
            if tag == "input" and attrs.get("type") == "password":
                if attrs.get("autocomplete") != "off":
                    vuln = self._create_vulnerability(
                        rule_id="security_misconfig",
                        title="Password Field Without Autocomplete=off",
                        description="Password field may be cached by browser",
                        location=f"{target}#{element.get('selector', 'input')}",
                        evidence="<input type='password'>",
                        remediation="Add autocomplete='off' to password fields",
                    )
                    vulnerabilities.append(vuln)

            # Check for links to external sites without rel=noopener
            if tag == "a":
                href = attrs.get("href", "")
                target_attr = attrs.get("target", "")
                rel = attrs.get("rel", "")

                if target_attr == "_blank" and "noopener" not in rel:
                    vuln = self._create_vulnerability(
                        rule_id="security_misconfig",
                        title="External Link Without noopener",
                        description="Links opening in new tab without rel='noopener' can be vulnerable to tabnabbing",
                        location=f"{target}#{element.get('selector', 'a')}",
                        evidence=f"<a href='{href}' target='_blank'>",
                        remediation="Add rel='noopener noreferrer' to external links",
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _scan_responses(
        self,
        responses: List[Dict[str, Any]],
        target: str,
    ) -> List[Vulnerability]:
        """Scan HTTP responses for vulnerabilities."""
        vulnerabilities = []

        for response in responses:
            headers = response.get("headers", {})
            body = response.get("body", "")
            url = response.get("url", target)
            status = response.get("status", 200)

            # Check security headers
            security_headers = {
                "Strict-Transport-Security": "HSTS header missing",
                "X-Content-Type-Options": "X-Content-Type-Options header missing",
                "X-Frame-Options": "X-Frame-Options header missing",
                "Content-Security-Policy": "CSP header missing",
                "X-XSS-Protection": "X-XSS-Protection header missing",
            }

            for header, message in security_headers.items():
                if header.lower() not in [h.lower() for h in headers.keys()]:
                    vuln = self._create_vulnerability(
                        rule_id="security_misconfig",
                        title=f"Missing Security Header: {header}",
                        description=message,
                        location=url,
                        evidence=f"Response headers: {list(headers.keys())}",
                        remediation=f"Add {header} header to all responses",
                    )
                    vulnerabilities.append(vuln)

            # Check for sensitive data in response
            for rule_id, rule in self._detection_rules.items():
                for pattern in rule["patterns"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        vuln = self._create_vulnerability(
                            rule_id=rule_id,
                            title=f"Potential {rule_id.replace('_', ' ').title()} Detected",
                            description=f"Response body matches pattern for {rule_id}",
                            location=url,
                            evidence=f"Pattern matched: {pattern}",
                            remediation=self._get_remediation(rule_id),
                        )
                        vulnerabilities.append(vuln)
                        break

            # Check for verbose error messages
            error_indicators = [
                "stack trace", "exception", "error in", "syntax error",
                "warning:", "fatal error", "mysql", "postgresql", "mongodb"
            ]
            for indicator in error_indicators:
                if indicator.lower() in body.lower():
                    vuln = self._create_vulnerability(
                        rule_id="security_misconfig",
                        title="Verbose Error Message Detected",
                        description="Response contains detailed error information that could aid attackers",
                        location=url,
                        evidence=f"Found indicator: {indicator}",
                        remediation="Configure application to show generic error messages in production",
                    )
                    vulnerabilities.append(vuln)
                    break

        return vulnerabilities

    def _passive_scan(self, target: str) -> List[Vulnerability]:
        """Perform passive vulnerability analysis."""
        vulnerabilities = []

        # Check URL for potential issues
        if "http://" in target and "localhost" not in target:
            vuln = self._create_vulnerability(
                rule_id="security_misconfig",
                title="Insecure HTTP Protocol",
                description="Target uses HTTP instead of HTTPS",
                location=target,
                evidence=f"URL: {target}",
                remediation="Use HTTPS for all communications",
            )
            vulnerabilities.append(vuln)

        # Check for common vulnerable paths
        vulnerable_paths = [
            "/admin", "/wp-admin", "/phpmyadmin", "/.git",
            "/.env", "/config", "/backup", "/api/debug"
        ]
        for path in vulnerable_paths:
            if path in target.lower():
                vuln = self._create_vulnerability(
                    rule_id="security_misconfig",
                    title="Sensitive Path Exposed",
                    description=f"URL contains potentially sensitive path: {path}",
                    location=target,
                    evidence=f"Path: {path}",
                    remediation="Restrict access to sensitive paths",
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _create_vulnerability(
        self,
        rule_id: str,
        title: str,
        description: str,
        location: str,
        evidence: str,
        remediation: str,
    ) -> Vulnerability:
        """Create a vulnerability finding."""
        self._vuln_counter += 1

        rule = self._detection_rules.get(rule_id, {})

        return Vulnerability(
            vuln_id=f"VULN-{self._vuln_counter:05d}",
            title=title,
            description=description,
            severity=rule.get("severity", VulnerabilitySeverity.MEDIUM),
            category=rule.get("category", VulnerabilityCategory.SECURITY_MISCONFIGURATION),
            location=location,
            evidence=evidence,
            remediation=remediation,
            cvss_score=rule.get("cvss", 5.0),
            cwe_id=rule.get("cwe"),
        )

    def _get_remediation(self, rule_id: str) -> str:
        """Get remediation advice for a rule."""
        remediations = {
            "sql_injection": "Use parameterized queries and prepared statements",
            "xss_reflected": "Sanitize and encode all user input before rendering",
            "xss_stored": "Sanitize input on storage and encode on output",
            "csrf_missing": "Implement CSRF tokens for all state-changing operations",
            "broken_auth": "Implement strong authentication and session management",
            "sensitive_data": "Remove sensitive data from responses and use encryption",
            "security_misconfig": "Review and harden security configuration",
            "insecure_cookies": "Set Secure, HttpOnly, and SameSite flags on cookies",
            "open_redirect": "Validate redirect URLs against a whitelist",
            "ssrf": "Validate and sanitize URLs, block internal addresses",
            "path_traversal": "Validate file paths and use allowlists",
            "command_injection": "Avoid shell commands, use safe APIs instead",
        }
        return remediations.get(rule_id, "Review and remediate the vulnerability")

    def _count_by_severity(
        self,
        vulnerabilities: List[Vulnerability],
    ) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {s.value: 0 for s in VulnerabilitySeverity}
        for vuln in vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts

    def _count_by_category(
        self,
        vulnerabilities: List[Vulnerability],
    ) -> Dict[str, int]:
        """Count vulnerabilities by category."""
        counts: Dict[str, int] = {}
        for vuln in vulnerabilities:
            cat = vuln.category.value
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def _calculate_risk_score(
        self,
        vulnerabilities: List[Vulnerability],
    ) -> float:
        """Calculate overall risk score (0-100)."""
        if not vulnerabilities:
            return 0.0

        # Weight by CVSS scores
        total_cvss = sum(v.cvss_score for v in vulnerabilities)
        max_possible = len(vulnerabilities) * 10

        # Factor in severity distribution
        severity_weights = {
            VulnerabilitySeverity.CRITICAL: 10,
            VulnerabilitySeverity.HIGH: 7,
            VulnerabilitySeverity.MEDIUM: 4,
            VulnerabilitySeverity.LOW: 2,
            VulnerabilitySeverity.INFO: 1,
        }

        severity_score = sum(
            severity_weights[v.severity] for v in vulnerabilities
        )
        max_severity = len(vulnerabilities) * 10

        # Combined score
        cvss_ratio = (total_cvss / max_possible) if max_possible > 0 else 0
        severity_ratio = (severity_score / max_severity) if max_severity > 0 else 0

        return round((cvss_ratio * 0.6 + severity_ratio * 0.4) * 100, 1)

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        """Get a scan result by ID."""
        for scan in self._scans:
            if scan.scan_id == scan_id:
                return scan
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics."""
        if not self._scans:
            return {
                "total_scans": 0,
                "total_vulnerabilities": 0,
            }

        total_vulns = sum(len(s.vulnerabilities) for s in self._scans)
        avg_risk = sum(s.risk_score for s in self._scans) / len(self._scans)

        all_vulns = [v for s in self._scans for v in s.vulnerabilities]
        by_severity = self._count_by_severity(all_vulns)
        by_category = self._count_by_category(all_vulns)

        return {
            "total_scans": len(self._scans),
            "total_vulnerabilities": total_vulns,
            "avg_risk_score": round(avg_risk, 1),
            "vulnerabilities_by_severity": by_severity,
            "vulnerabilities_by_category": by_category,
            "detection_rules": len(self._detection_rules),
        }

    def format_result(self, result: ScanResult) -> str:
        """Format scan result for display."""
        risk_status = "CRITICAL" if result.risk_score >= 80 else \
                     "HIGH" if result.risk_score >= 60 else \
                     "MEDIUM" if result.risk_score >= 40 else \
                     "LOW" if result.risk_score >= 20 else "MINIMAL"

        lines = [
            "=" * 60,
            f"  SECURITY SCAN RESULT: {risk_status} RISK",
            "=" * 60,
            "",
            f"  Scan ID: {result.scan_id}",
            f"  Target: {result.target}",
            f"  Type: {result.scan_type}",
            f"  Duration: {(result.completed_at - result.started_at).total_seconds():.2f}s",
            "",
            "-" * 60,
            "  FINDINGS SUMMARY",
            "-" * 60,
            "",
            f"  Risk Score: {result.risk_score}/100",
            f"  Total Vulnerabilities: {len(result.vulnerabilities)}",
            "",
            "  By Severity:",
        ]

        severity_icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "ℹ️",
        }

        for severity, count in result.findings_by_severity.items():
            if count > 0:
                icon = severity_icons.get(severity, "")
                lines.append(f"    {icon} {severity}: {count}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_vulnerability_scanner(
    scan_depth: str = "standard",
    timeout: int = 30000,
) -> VulnerabilityScanner:
    """Create a vulnerability scanner instance."""
    return VulnerabilityScanner(
        scan_depth=scan_depth,
        timeout=timeout,
    )
