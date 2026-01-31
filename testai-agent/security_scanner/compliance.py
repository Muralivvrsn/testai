"""
TestAI Agent - Security Compliance Checker

Compliance checking against security standards
like PCI-DSS, OWASP, HIPAA, and SOC2.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import uuid


class ComplianceStandard(Enum):
    """Security compliance standards."""
    OWASP_TOP_10 = "owasp_top_10"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    GDPR = "gdpr"
    NIST = "nist"
    ISO_27001 = "iso_27001"
    CIS = "cis"


class ComplianceLevel(Enum):
    """Compliance levels."""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ComplianceRequirement:
    """A compliance requirement."""
    req_id: str
    standard: ComplianceStandard
    title: str
    description: str
    controls: List[str]
    severity: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceViolation:
    """A compliance violation."""
    violation_id: str
    requirement: ComplianceRequirement
    finding: str
    evidence: str
    remediation: str
    severity: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceResult:
    """Result of a compliance check."""
    result_id: str
    standard: ComplianceStandard
    target: str
    level: ComplianceLevel
    requirements_checked: int
    requirements_passed: int
    requirements_failed: int
    violations: List[ComplianceViolation]
    score: float
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class ComplianceChecker:
    """
    Security compliance checker.

    Features:
    - Multiple standards support
    - Requirement mapping
    - Gap analysis
    - Remediation guidance
    """

    def __init__(
        self,
        standards: Optional[List[ComplianceStandard]] = None,
    ):
        """Initialize the compliance checker."""
        self._enabled_standards = standards or [ComplianceStandard.OWASP_TOP_10]
        self._requirements: Dict[str, ComplianceRequirement] = {}
        self._results: List[ComplianceResult] = []
        self._req_counter = 0
        self._violation_counter = 0
        self._result_counter = 0

        # Initialize requirements
        self._init_requirements()

    def _init_requirements(self):
        """Initialize compliance requirements."""
        owasp_requirements = [
            ComplianceRequirement(
                req_id="OWASP-A01",
                standard=ComplianceStandard.OWASP_TOP_10,
                title="Broken Access Control",
                description="Implement proper access control mechanisms",
                controls=[
                    "Deny by default",
                    "Implement proper authentication",
                    "Rate limiting on APIs",
                    "Disable directory listing",
                    "JWT validation",
                ],
                severity="critical",
            ),
            ComplianceRequirement(
                req_id="OWASP-A02",
                standard=ComplianceStandard.OWASP_TOP_10,
                title="Cryptographic Failures",
                description="Protect sensitive data with proper encryption",
                controls=[
                    "Use TLS 1.2+",
                    "Encrypt data at rest",
                    "Strong password hashing",
                    "Secure key management",
                    "No hardcoded secrets",
                ],
                severity="critical",
            ),
            ComplianceRequirement(
                req_id="OWASP-A03",
                standard=ComplianceStandard.OWASP_TOP_10,
                title="Injection",
                description="Prevent injection attacks",
                controls=[
                    "Parameterized queries",
                    "Input validation",
                    "Output encoding",
                    "Escape special characters",
                    "Use ORM/prepared statements",
                ],
                severity="critical",
            ),
            ComplianceRequirement(
                req_id="OWASP-A04",
                standard=ComplianceStandard.OWASP_TOP_10,
                title="Insecure Design",
                description="Implement secure design patterns",
                controls=[
                    "Threat modeling",
                    "Secure development lifecycle",
                    "Security requirements",
                    "Reference architecture",
                ],
                severity="high",
            ),
            ComplianceRequirement(
                req_id="OWASP-A05",
                standard=ComplianceStandard.OWASP_TOP_10,
                title="Security Misconfiguration",
                description="Properly configure security settings",
                controls=[
                    "Hardened configurations",
                    "Remove default credentials",
                    "Security headers configured",
                    "Error handling",
                    "Disable unnecessary features",
                ],
                severity="high",
            ),
            ComplianceRequirement(
                req_id="OWASP-A06",
                standard=ComplianceStandard.OWASP_TOP_10,
                title="Vulnerable Components",
                description="Keep components updated",
                controls=[
                    "Component inventory",
                    "Remove unused dependencies",
                    "Monitor CVEs",
                    "Regular updates",
                    "SCA scanning",
                ],
                severity="high",
            ),
            ComplianceRequirement(
                req_id="OWASP-A07",
                standard=ComplianceStandard.OWASP_TOP_10,
                title="Authentication Failures",
                description="Implement secure authentication",
                controls=[
                    "Multi-factor authentication",
                    "Secure session management",
                    "Password policies",
                    "Account lockout",
                    "Credential stuffing protection",
                ],
                severity="critical",
            ),
            ComplianceRequirement(
                req_id="OWASP-A08",
                standard=ComplianceStandard.OWASP_TOP_10,
                title="Data Integrity Failures",
                description="Ensure data integrity",
                controls=[
                    "Verify software integrity",
                    "Secure CI/CD pipeline",
                    "Code signing",
                    "Integrity checks",
                ],
                severity="high",
            ),
            ComplianceRequirement(
                req_id="OWASP-A09",
                standard=ComplianceStandard.OWASP_TOP_10,
                title="Security Logging Failures",
                description="Implement comprehensive logging",
                controls=[
                    "Log security events",
                    "Centralized logging",
                    "Log integrity",
                    "Alert on suspicious activity",
                    "Audit trails",
                ],
                severity="medium",
            ),
            ComplianceRequirement(
                req_id="OWASP-A10",
                standard=ComplianceStandard.OWASP_TOP_10,
                title="SSRF",
                description="Prevent Server-Side Request Forgery",
                controls=[
                    "Validate URLs",
                    "Whitelist allowed destinations",
                    "Block internal addresses",
                    "Network segmentation",
                ],
                severity="high",
            ),
        ]

        pci_requirements = [
            ComplianceRequirement(
                req_id="PCI-1",
                standard=ComplianceStandard.PCI_DSS,
                title="Install and maintain a firewall",
                description="Network security controls",
                controls=[
                    "Firewall configuration",
                    "DMZ implementation",
                    "Network segmentation",
                ],
                severity="critical",
            ),
            ComplianceRequirement(
                req_id="PCI-3",
                standard=ComplianceStandard.PCI_DSS,
                title="Protect stored cardholder data",
                description="Data protection at rest",
                controls=[
                    "Encryption of card data",
                    "Key management",
                    "Minimize data storage",
                    "Mask PAN when displayed",
                ],
                severity="critical",
            ),
            ComplianceRequirement(
                req_id="PCI-4",
                standard=ComplianceStandard.PCI_DSS,
                title="Encrypt transmission",
                description="Protect data in transit",
                controls=[
                    "TLS for all transmissions",
                    "Strong cryptography",
                    "Certificate management",
                ],
                severity="critical",
            ),
            ComplianceRequirement(
                req_id="PCI-6",
                standard=ComplianceStandard.PCI_DSS,
                title="Develop secure systems",
                description="Secure development practices",
                controls=[
                    "Secure coding guidelines",
                    "Code review",
                    "Vulnerability testing",
                    "Change control",
                ],
                severity="high",
            ),
            ComplianceRequirement(
                req_id="PCI-8",
                standard=ComplianceStandard.PCI_DSS,
                title="Identify and authenticate access",
                description="Access control requirements",
                controls=[
                    "Unique user IDs",
                    "Strong authentication",
                    "Password management",
                    "MFA for remote access",
                ],
                severity="critical",
            ),
        ]

        gdpr_requirements = [
            ComplianceRequirement(
                req_id="GDPR-7",
                standard=ComplianceStandard.GDPR,
                title="Data Protection by Design",
                description="Privacy by design and default",
                controls=[
                    "Minimize data collection",
                    "Purpose limitation",
                    "Data anonymization",
                    "Privacy impact assessment",
                ],
                severity="high",
            ),
            ComplianceRequirement(
                req_id="GDPR-32",
                standard=ComplianceStandard.GDPR,
                title="Security of Processing",
                description="Technical security measures",
                controls=[
                    "Encryption",
                    "Pseudonymization",
                    "Access controls",
                    "Regular testing",
                ],
                severity="high",
            ),
            ComplianceRequirement(
                req_id="GDPR-33",
                standard=ComplianceStandard.GDPR,
                title="Breach Notification",
                description="Data breach response",
                controls=[
                    "Breach detection",
                    "72-hour notification",
                    "Breach documentation",
                    "User notification",
                ],
                severity="critical",
            ),
        ]

        all_requirements = owasp_requirements + pci_requirements + gdpr_requirements

        for req in all_requirements:
            self._requirements[req.req_id] = req

    def add_requirement(
        self,
        standard: ComplianceStandard,
        title: str,
        description: str,
        controls: List[str],
        severity: str = "medium",
        req_id: Optional[str] = None,
    ) -> ComplianceRequirement:
        """Add a custom requirement."""
        if req_id is None:
            self._req_counter += 1
            req_id = f"CUSTOM-{self._req_counter:03d}"

        requirement = ComplianceRequirement(
            req_id=req_id,
            standard=standard,
            title=title,
            description=description,
            controls=controls,
            severity=severity,
        )

        self._requirements[req_id] = requirement
        return requirement

    def get_requirement(self, req_id: str) -> Optional[ComplianceRequirement]:
        """Get a requirement by ID."""
        return self._requirements.get(req_id)

    def get_requirements_by_standard(
        self,
        standard: ComplianceStandard,
    ) -> List[ComplianceRequirement]:
        """Get requirements for a specific standard."""
        return [
            r for r in self._requirements.values()
            if r.standard == standard
        ]

    def check(
        self,
        target: str,
        standard: ComplianceStandard,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> ComplianceResult:
        """
        Check compliance against a standard.

        Args:
            target: Target identifier
            standard: Standard to check against
            findings: Optional list of security findings
        """
        self._result_counter += 1
        result_id = f"COMPLIANCE-{self._result_counter:05d}"

        requirements = self.get_requirements_by_standard(standard)
        violations: List[ComplianceViolation] = []

        # Map findings to requirement violations
        if findings:
            for finding in findings:
                mapped_req = self._map_finding_to_requirement(finding, requirements)
                if mapped_req:
                    self._violation_counter += 1
                    violation = ComplianceViolation(
                        violation_id=f"VIOL-{self._violation_counter:05d}",
                        requirement=mapped_req,
                        finding=finding.get("title", "Unknown finding"),
                        evidence=finding.get("evidence", ""),
                        remediation=finding.get("remediation", mapped_req.controls[0] if mapped_req.controls else "Review and remediate"),
                        severity=finding.get("severity", "medium"),
                    )
                    violations.append(violation)

        # Calculate compliance metrics
        requirements_checked = len(requirements)
        failed_req_ids = {v.requirement.req_id for v in violations}
        requirements_failed = len(failed_req_ids)
        requirements_passed = requirements_checked - requirements_failed

        # Calculate score
        score = (requirements_passed / requirements_checked * 100) if requirements_checked > 0 else 100

        # Determine compliance level
        if score >= 100:
            level = ComplianceLevel.COMPLIANT
        elif score >= 70:
            level = ComplianceLevel.PARTIALLY_COMPLIANT
        else:
            level = ComplianceLevel.NON_COMPLIANT

        result = ComplianceResult(
            result_id=result_id,
            standard=standard,
            target=target,
            level=level,
            requirements_checked=requirements_checked,
            requirements_passed=requirements_passed,
            requirements_failed=requirements_failed,
            violations=violations,
            score=round(score, 1),
            timestamp=datetime.now(),
        )

        self._results.append(result)
        return result

    def _map_finding_to_requirement(
        self,
        finding: Dict[str, Any],
        requirements: List[ComplianceRequirement],
    ) -> Optional[ComplianceRequirement]:
        """Map a security finding to a compliance requirement."""
        category = finding.get("category", "").lower()
        title = finding.get("title", "").lower()

        # Mapping rules
        mappings = {
            "injection": ["OWASP-A03"],
            "sql": ["OWASP-A03"],
            "xss": ["OWASP-A03"],
            "access control": ["OWASP-A01"],
            "authentication": ["OWASP-A07", "PCI-8"],
            "session": ["OWASP-A07"],
            "crypto": ["OWASP-A02", "PCI-3", "PCI-4"],
            "encryption": ["OWASP-A02", "PCI-3", "PCI-4"],
            "config": ["OWASP-A05"],
            "header": ["OWASP-A05"],
            "component": ["OWASP-A06"],
            "logging": ["OWASP-A09"],
            "ssrf": ["OWASP-A10"],
            "data": ["GDPR-7", "GDPR-32"],
        }

        for keyword, req_ids in mappings.items():
            if keyword in category or keyword in title:
                for req_id in req_ids:
                    req = self._requirements.get(req_id)
                    if req and req in requirements:
                        return req

        return None

    def check_all(
        self,
        target: str,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[ComplianceResult]:
        """Check compliance against all enabled standards."""
        results = []

        for standard in self._enabled_standards:
            result = self.check(target, standard, findings)
            results.append(result)

        return results

    def get_gap_analysis(
        self,
        result: ComplianceResult,
    ) -> Dict[str, Any]:
        """Generate a gap analysis from a compliance result."""
        gaps = []

        for violation in result.violations:
            gaps.append({
                "requirement": violation.requirement.req_id,
                "title": violation.requirement.title,
                "finding": violation.finding,
                "severity": violation.severity,
                "controls_needed": violation.requirement.controls,
                "remediation": violation.remediation,
            })

        return {
            "standard": result.standard.value,
            "compliance_level": result.level.value,
            "score": result.score,
            "total_gaps": len(gaps),
            "gaps": gaps,
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get checker statistics."""
        if not self._results:
            return {
                "total_requirements": len(self._requirements),
                "total_checks": 0,
            }

        level_counts = {l.value: 0 for l in ComplianceLevel}
        for result in self._results:
            level_counts[result.level.value] += 1

        standard_counts: Dict[str, int] = {}
        for req in self._requirements.values():
            std = req.standard.value
            standard_counts[std] = standard_counts.get(std, 0) + 1

        avg_score = sum(r.score for r in self._results) / len(self._results)

        return {
            "total_requirements": len(self._requirements),
            "total_checks": len(self._results),
            "total_violations": sum(len(r.violations) for r in self._results),
            "avg_compliance_score": round(avg_score, 1),
            "compliance_levels": level_counts,
            "requirements_by_standard": standard_counts,
        }

    def format_result(self, result: ComplianceResult) -> str:
        """Format compliance result for display."""
        level_icons = {
            ComplianceLevel.COMPLIANT: "✅ COMPLIANT",
            ComplianceLevel.PARTIALLY_COMPLIANT: "⚠️ PARTIALLY COMPLIANT",
            ComplianceLevel.NON_COMPLIANT: "❌ NON-COMPLIANT",
            ComplianceLevel.NOT_APPLICABLE: "➖ NOT APPLICABLE",
        }

        lines = [
            "=" * 60,
            f"  COMPLIANCE CHECK: {level_icons.get(result.level, 'UNKNOWN')}",
            "=" * 60,
            "",
            f"  Standard: {result.standard.value}",
            f"  Target: {result.target}",
            f"  Score: {result.score}%",
            "",
            "-" * 60,
            "  REQUIREMENTS",
            "-" * 60,
            "",
            f"  Checked: {result.requirements_checked}",
            f"  Passed: {result.requirements_passed}",
            f"  Failed: {result.requirements_failed}",
            "",
        ]

        if result.violations:
            lines.extend([
                "-" * 60,
                "  VIOLATIONS",
                "-" * 60,
                "",
            ])

            for violation in result.violations[:5]:
                lines.append(f"  • {violation.requirement.req_id}: {violation.finding}")

            if len(result.violations) > 5:
                lines.append(f"  ... and {len(result.violations) - 5} more")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_compliance_checker(
    standards: Optional[List[ComplianceStandard]] = None,
) -> ComplianceChecker:
    """Create a compliance checker instance."""
    return ComplianceChecker(standards=standards)
