"""
TestAI Agent - Attack Simulator

Simulated security attacks for penetration testing
with safe payloads and configurable aggressiveness.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import uuid


class AttackType(Enum):
    """Types of security attacks."""
    SQL_INJECTION = "sql_injection"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    CSRF = "csrf"
    AUTH_BYPASS = "auth_bypass"
    BRUTE_FORCE = "brute_force"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    IDOR = "idor"
    FILE_UPLOAD = "file_upload"
    XXE = "xxe"
    LDAP_INJECTION = "ldap_injection"
    HEADER_INJECTION = "header_injection"


class AttackOutcome(Enum):
    """Outcome of an attack simulation."""
    VULNERABLE = "vulnerable"
    POTENTIALLY_VULNERABLE = "potentially_vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass
class Attack:
    """An attack definition."""
    attack_id: str
    name: str
    attack_type: AttackType
    description: str
    payloads: List[str]
    detection_indicators: List[str]
    risk_level: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackResult:
    """Result of an attack simulation."""
    result_id: str
    attack: Attack
    target: str
    outcome: AttackOutcome
    payload_used: str
    response_indicators: List[str]
    evidence: str
    timestamp: datetime
    duration_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class AttackSimulator:
    """
    Security attack simulator.

    Features:
    - Safe payload generation
    - Multiple attack types
    - Response analysis
    - Evidence collection
    """

    def __init__(
        self,
        mode: str = "safe",
        max_payloads: int = 10,
    ):
        """Initialize the simulator."""
        self._mode = mode
        self._max_payloads = max_payloads
        self._attacks: Dict[str, Attack] = {}
        self._results: List[AttackResult] = []
        self._attack_counter = 0
        self._result_counter = 0

        # Initialize built-in attacks
        self._init_builtin_attacks()

    def _init_builtin_attacks(self):
        """Initialize built-in attack definitions."""
        builtin_attacks = [
            Attack(
                attack_id="sqli-basic",
                name="Basic SQL Injection",
                attack_type=AttackType.SQL_INJECTION,
                description="Test for basic SQL injection vulnerabilities",
                payloads=[
                    "' OR '1'='1",
                    "' OR '1'='1' --",
                    "1; DROP TABLE users--",
                    "' UNION SELECT NULL--",
                    "admin'--",
                    "1' AND '1'='1",
                    "'; SELECT * FROM users--",
                ],
                detection_indicators=[
                    "sql", "syntax", "error", "mysql", "postgresql",
                    "sqlite", "oracle", "you have an error",
                ],
                risk_level="critical",
            ),
            Attack(
                attack_id="xss-basic",
                name="Basic XSS",
                attack_type=AttackType.XSS_REFLECTED,
                description="Test for reflected XSS vulnerabilities",
                payloads=[
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<body onload=alert('XSS')>",
                    "'\"><script>alert('XSS')</script>",
                    "<iframe src=\"javascript:alert('XSS')\">",
                ],
                detection_indicators=[
                    "<script>", "alert(", "onerror=", "onload=",
                ],
                risk_level="high",
            ),
            Attack(
                attack_id="xss-dom",
                name="DOM-based XSS",
                attack_type=AttackType.XSS_REFLECTED,
                description="Test for DOM-based XSS vulnerabilities",
                payloads=[
                    "#<script>alert('XSS')</script>",
                    "?name=<script>alert('XSS')</script>",
                    "<img/src=x onerror=alert('XSS')>",
                    "<svg/onload=alert('XSS')>",
                ],
                detection_indicators=[
                    "innerhtml", "document.write", "eval(",
                ],
                risk_level="high",
            ),
            Attack(
                attack_id="path-traversal",
                name="Path Traversal",
                attack_type=AttackType.PATH_TRAVERSAL,
                description="Test for directory traversal vulnerabilities",
                payloads=[
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\config\\sam",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252f..%252f..%252fetc%252fpasswd",
                ],
                detection_indicators=[
                    "root:", "/etc/passwd", "file not found",
                    "permission denied", "access denied",
                ],
                risk_level="high",
            ),
            Attack(
                attack_id="cmd-injection",
                name="Command Injection",
                attack_type=AttackType.COMMAND_INJECTION,
                description="Test for OS command injection",
                payloads=[
                    "; ls -la",
                    "| whoami",
                    "`id`",
                    "$(cat /etc/passwd)",
                    "&& dir",
                    "|| echo vulnerable",
                ],
                detection_indicators=[
                    "uid=", "gid=", "root", "bin/", "volume serial",
                ],
                risk_level="critical",
            ),
            Attack(
                attack_id="ssrf-basic",
                name="Basic SSRF",
                attack_type=AttackType.SSRF,
                description="Test for Server-Side Request Forgery",
                payloads=[
                    "http://localhost/admin",
                    "http://127.0.0.1/",
                    "http://169.254.169.254/latest/meta-data/",
                    "http://[::1]/",
                    "http://0.0.0.0/",
                    "file:///etc/passwd",
                ],
                detection_indicators=[
                    "localhost", "127.0.0.1", "metadata", "admin",
                ],
                risk_level="high",
            ),
            Attack(
                attack_id="open-redirect",
                name="Open Redirect",
                attack_type=AttackType.OPEN_REDIRECT,
                description="Test for open redirect vulnerabilities",
                payloads=[
                    "//evil.com",
                    "https://evil.com",
                    "/\\evil.com",
                    "//evil.com/%2f..",
                    "javascript:alert('redirect')",
                ],
                detection_indicators=[
                    "redirect", "location:", "302", "301",
                ],
                risk_level="medium",
            ),
            Attack(
                attack_id="auth-bypass",
                name="Authentication Bypass",
                attack_type=AttackType.AUTH_BYPASS,
                description="Test for authentication bypass",
                payloads=[
                    "admin' --",
                    "admin'/*",
                    "' or 1=1--",
                    "') or ('1'='1",
                ],
                detection_indicators=[
                    "welcome", "dashboard", "logged in", "admin",
                ],
                risk_level="critical",
            ),
            Attack(
                attack_id="idor-basic",
                name="IDOR",
                attack_type=AttackType.IDOR,
                description="Test for Insecure Direct Object Reference",
                payloads=[
                    "1", "2", "0", "-1", "999999", "1+1", "1'",
                ],
                detection_indicators=[
                    "unauthorized", "forbidden", "not found",
                    "different user", "other user's data",
                ],
                risk_level="high",
            ),
            Attack(
                attack_id="header-injection",
                name="Header Injection",
                attack_type=AttackType.HEADER_INJECTION,
                description="Test for HTTP header injection",
                payloads=[
                    "value\r\nX-Injected: header",
                    "value%0d%0aX-Injected:%20header",
                    "value\nSet-Cookie: injected=true",
                ],
                detection_indicators=[
                    "x-injected", "set-cookie", "location:",
                ],
                risk_level="medium",
            ),
        ]

        for attack in builtin_attacks:
            self._attacks[attack.attack_id] = attack

    def add_attack(
        self,
        name: str,
        attack_type: AttackType,
        description: str,
        payloads: List[str],
        detection_indicators: List[str],
        risk_level: str = "medium",
        attack_id: Optional[str] = None,
    ) -> Attack:
        """Add a custom attack definition."""
        if attack_id is None:
            self._attack_counter += 1
            attack_id = f"custom-{self._attack_counter:03d}"

        attack = Attack(
            attack_id=attack_id,
            name=name,
            attack_type=attack_type,
            description=description,
            payloads=payloads[:self._max_payloads],
            detection_indicators=detection_indicators,
            risk_level=risk_level,
        )

        self._attacks[attack_id] = attack
        return attack

    def get_attack(self, attack_id: str) -> Optional[Attack]:
        """Get an attack by ID."""
        return self._attacks.get(attack_id)

    def get_attacks_by_type(
        self,
        attack_type: AttackType,
    ) -> List[Attack]:
        """Get attacks by type."""
        return [
            a for a in self._attacks.values()
            if a.attack_type == attack_type
        ]

    def simulate(
        self,
        attack_id: str,
        target: str,
        response: Optional[Dict[str, Any]] = None,
    ) -> Optional[AttackResult]:
        """
        Simulate an attack against a target.

        Args:
            attack_id: ID of the attack to simulate
            target: Target URL or identifier
            response: Simulated response for analysis
        """
        attack = self._attacks.get(attack_id)
        if not attack:
            return None

        self._result_counter += 1
        result_id = f"RESULT-{self._result_counter:05d}"

        start_time = datetime.now()

        # Simulate attack with first payload
        payload = attack.payloads[0] if attack.payloads else ""
        outcome = AttackOutcome.NOT_VULNERABLE
        evidence = ""
        response_indicators: List[str] = []

        if response:
            body = response.get("body", "").lower()
            headers = response.get("headers", {})
            status = response.get("status", 200)

            # Check for indicators in response
            for indicator in attack.detection_indicators:
                if indicator.lower() in body:
                    response_indicators.append(indicator)

            # Determine outcome based on indicators
            if response_indicators:
                # Check if payload is reflected (potential XSS/injection)
                if payload.lower() in body:
                    outcome = AttackOutcome.VULNERABLE
                    evidence = f"Payload reflected in response: {payload}"
                else:
                    outcome = AttackOutcome.POTENTIALLY_VULNERABLE
                    evidence = f"Response contains indicators: {response_indicators}"
            elif status in [403, 429]:
                outcome = AttackOutcome.BLOCKED
                evidence = f"Request blocked with status {status}"
            elif status >= 500:
                outcome = AttackOutcome.ERROR
                evidence = f"Server error: {status}"

        duration = (datetime.now() - start_time).total_seconds() * 1000

        result = AttackResult(
            result_id=result_id,
            attack=attack,
            target=target,
            outcome=outcome,
            payload_used=payload,
            response_indicators=response_indicators,
            evidence=evidence,
            timestamp=start_time,
            duration_ms=duration,
        )

        self._results.append(result)
        return result

    def simulate_all(
        self,
        target: str,
        attack_types: Optional[List[AttackType]] = None,
        response: Optional[Dict[str, Any]] = None,
    ) -> List[AttackResult]:
        """Simulate all matching attacks against a target."""
        results = []

        for attack in self._attacks.values():
            if attack_types and attack.attack_type not in attack_types:
                continue

            result = self.simulate(attack.attack_id, target, response)
            if result:
                results.append(result)

        return results

    def get_payloads(
        self,
        attack_type: AttackType,
        limit: int = 10,
    ) -> List[str]:
        """Get payloads for a specific attack type."""
        payloads = []

        for attack in self._attacks.values():
            if attack.attack_type == attack_type:
                payloads.extend(attack.payloads)

        return payloads[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """Get simulator statistics."""
        if not self._results:
            return {
                "total_attacks": len(self._attacks),
                "total_simulations": 0,
            }

        outcome_counts = {o.value: 0 for o in AttackOutcome}
        for result in self._results:
            outcome_counts[result.outcome.value] += 1

        type_counts: Dict[str, int] = {}
        for attack in self._attacks.values():
            type_name = attack.attack_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        return {
            "total_attacks": len(self._attacks),
            "total_simulations": len(self._results),
            "outcomes": outcome_counts,
            "attacks_by_type": type_counts,
            "vulnerable_found": outcome_counts.get("vulnerable", 0),
            "potentially_vulnerable": outcome_counts.get("potentially_vulnerable", 0),
        }

    def format_result(self, result: AttackResult) -> str:
        """Format attack result for display."""
        outcome_icons = {
            AttackOutcome.VULNERABLE: "🔴 VULNERABLE",
            AttackOutcome.POTENTIALLY_VULNERABLE: "🟠 POTENTIALLY VULNERABLE",
            AttackOutcome.NOT_VULNERABLE: "🟢 NOT VULNERABLE",
            AttackOutcome.BLOCKED: "🛡️ BLOCKED",
            AttackOutcome.ERROR: "⚠️ ERROR",
        }

        lines = [
            "=" * 50,
            "  ATTACK SIMULATION RESULT",
            "=" * 50,
            "",
            f"  {outcome_icons.get(result.outcome, 'UNKNOWN')}",
            "",
            f"  Attack: {result.attack.name}",
            f"  Type: {result.attack.attack_type.value}",
            f"  Target: {result.target}",
            f"  Duration: {result.duration_ms:.2f}ms",
            "",
            "-" * 50,
            f"  Payload: {result.payload_used[:50]}...",
            "",
        ]

        if result.evidence:
            lines.append(f"  Evidence: {result.evidence}")

        if result.response_indicators:
            lines.append(f"  Indicators: {', '.join(result.response_indicators)}")

        lines.extend(["", "=" * 50])
        return "\n".join(lines)


def create_attack_simulator(
    mode: str = "safe",
    max_payloads: int = 10,
) -> AttackSimulator:
    """Create an attack simulator instance."""
    return AttackSimulator(
        mode=mode,
        max_payloads=max_payloads,
    )
