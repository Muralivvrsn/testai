"""
TestAI Agent - Security Module

Comprehensive security testing focused on OWASP vulnerabilities
and common web application security issues.
"""

from .vulnerability_scanner import (
    VulnerabilityScanner,
    VulnerabilityType,
    Vulnerability,
    ScanResult,
    SeverityLevel,
    create_scanner,
)

from .security_test_generator import (
    SecurityTestGenerator,
    SecurityTestCase,
    SecurityCategory,
    create_security_generator,
)

__all__ = [
    # Vulnerability Scanner
    "VulnerabilityScanner",
    "VulnerabilityType",
    "Vulnerability",
    "ScanResult",
    "SeverityLevel",
    "create_scanner",
    # Security Test Generator
    "SecurityTestGenerator",
    "SecurityTestCase",
    "SecurityCategory",
    "create_security_generator",
]
