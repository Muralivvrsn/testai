"""
TestAI Agent - API Mocker

Mock API responses for testing, with
rule-based matching and response simulation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable, Pattern
import uuid
import re


class MatchType(Enum):
    """Types of URL matching."""
    EXACT = "exact"
    PREFIX = "prefix"
    REGEX = "regex"
    CONTAINS = "contains"


class DelayType(Enum):
    """Types of response delays."""
    NONE = "none"
    FIXED = "fixed"
    RANDOM = "random"
    SLOW = "slow"


@dataclass
class MockResponse:
    """A mock API response."""
    status_code: int
    body: Any
    headers: Dict[str, str] = field(default_factory=dict)
    delay_ms: int = 0


@dataclass
class MockRule:
    """A rule for matching and responding to requests."""
    rule_id: str
    name: str
    method: str  # GET, POST, etc. or * for any
    url_pattern: str
    match_type: MatchType
    response: MockResponse
    conditions: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    hit_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class MockRequest:
    """A recorded mock request."""
    request_id: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Any
    matched_rule: Optional[str]
    timestamp: datetime


class APIMocker:
    """
    API mocking service.

    Features:
    - Rule-based response matching
    - Request recording
    - Response customization
    - Conditional matching
    - Delay simulation
    """

    def __init__(
        self,
        default_delay_ms: int = 0,
    ):
        """Initialize the mocker."""
        self._default_delay = default_delay_ms
        self._rules: Dict[str, MockRule] = {}
        self._requests: List[MockRequest] = []

        self._rule_counter = 0
        self._request_counter = 0

    def add_rule(
        self,
        name: str,
        method: str,
        url_pattern: str,
        status_code: int,
        body: Any = None,
        headers: Optional[Dict[str, str]] = None,
        match_type: MatchType = MatchType.PREFIX,
        delay_ms: int = 0,
        conditions: Optional[Dict[str, Any]] = None,
        priority: int = 0,
    ) -> MockRule:
        """Add a mock rule."""
        self._rule_counter += 1
        rule_id = f"MOCK-{self._rule_counter:05d}"

        response = MockResponse(
            status_code=status_code,
            body=body or {},
            headers=headers or {"Content-Type": "application/json"},
            delay_ms=delay_ms,
        )

        rule = MockRule(
            rule_id=rule_id,
            name=name,
            method=method.upper(),
            url_pattern=url_pattern,
            match_type=match_type,
            response=response,
            conditions=conditions or {},
            priority=priority,
        )

        self._rules[rule_id] = rule
        return rule

    def add_get(
        self,
        url_pattern: str,
        status_code: int = 200,
        body: Any = None,
        **kwargs,
    ) -> MockRule:
        """Add a GET mock rule."""
        return self.add_rule(
            name=f"GET {url_pattern}",
            method="GET",
            url_pattern=url_pattern,
            status_code=status_code,
            body=body,
            **kwargs,
        )

    def add_post(
        self,
        url_pattern: str,
        status_code: int = 201,
        body: Any = None,
        **kwargs,
    ) -> MockRule:
        """Add a POST mock rule."""
        return self.add_rule(
            name=f"POST {url_pattern}",
            method="POST",
            url_pattern=url_pattern,
            status_code=status_code,
            body=body,
            **kwargs,
        )

    def add_put(
        self,
        url_pattern: str,
        status_code: int = 200,
        body: Any = None,
        **kwargs,
    ) -> MockRule:
        """Add a PUT mock rule."""
        return self.add_rule(
            name=f"PUT {url_pattern}",
            method="PUT",
            url_pattern=url_pattern,
            status_code=status_code,
            body=body,
            **kwargs,
        )

    def add_delete(
        self,
        url_pattern: str,
        status_code: int = 204,
        **kwargs,
    ) -> MockRule:
        """Add a DELETE mock rule."""
        return self.add_rule(
            name=f"DELETE {url_pattern}",
            method="DELETE",
            url_pattern=url_pattern,
            status_code=status_code,
            body=None,
            **kwargs,
        )

    def add_error(
        self,
        url_pattern: str,
        status_code: int = 500,
        error_message: str = "Internal Server Error",
        **kwargs,
    ) -> MockRule:
        """Add an error mock rule."""
        return self.add_rule(
            name=f"ERROR {url_pattern}",
            method="*",
            url_pattern=url_pattern,
            status_code=status_code,
            body={"error": error_message},
            **kwargs,
        )

    def match(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Any = None,
    ) -> Optional[MockResponse]:
        """Match a request to a rule and return response."""
        self._request_counter += 1
        request_id = f"MREQ-{self._request_counter:05d}"

        matched_rule = None
        best_priority = -float("inf")

        for rule in self._rules.values():
            if self._matches_rule(rule, method, url, headers, body):
                if rule.priority > best_priority:
                    matched_rule = rule
                    best_priority = rule.priority

        # Record request
        self._requests.append(MockRequest(
            request_id=request_id,
            method=method,
            url=url,
            headers=headers or {},
            body=body,
            matched_rule=matched_rule.rule_id if matched_rule else None,
            timestamp=datetime.now(),
        ))

        if matched_rule:
            matched_rule.hit_count += 1
            return matched_rule.response

        return None

    def _matches_rule(
        self,
        rule: MockRule,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]],
        body: Any,
    ) -> bool:
        """Check if a request matches a rule."""
        # Check method
        if rule.method != "*" and rule.method != method.upper():
            return False

        # Check URL pattern
        if not self._matches_url(rule.url_pattern, url, rule.match_type):
            return False

        # Check conditions
        if not self._matches_conditions(rule.conditions, headers, body):
            return False

        return True

    def _matches_url(
        self,
        pattern: str,
        url: str,
        match_type: MatchType,
    ) -> bool:
        """Check if URL matches pattern."""
        if match_type == MatchType.EXACT:
            return pattern == url

        elif match_type == MatchType.PREFIX:
            return url.startswith(pattern) or pattern in url

        elif match_type == MatchType.REGEX:
            try:
                return bool(re.match(pattern, url))
            except re.error:
                return False

        elif match_type == MatchType.CONTAINS:
            return pattern in url

        return False

    def _matches_conditions(
        self,
        conditions: Dict[str, Any],
        headers: Optional[Dict[str, str]],
        body: Any,
    ) -> bool:
        """Check if conditions are met."""
        if not conditions:
            return True

        # Header conditions
        header_conditions = conditions.get("headers", {})
        if header_conditions:
            for key, value in header_conditions.items():
                if not headers or headers.get(key) != value:
                    return False

        # Body conditions
        body_conditions = conditions.get("body", {})
        if body_conditions and isinstance(body, dict):
            for key, value in body_conditions.items():
                if body.get(key) != value:
                    return False

        return True

    def get_requests(
        self,
        method: Optional[str] = None,
        url_contains: Optional[str] = None,
        limit: int = 50,
    ) -> List[MockRequest]:
        """Get recorded requests."""
        requests = self._requests

        if method:
            requests = [r for r in requests if r.method == method.upper()]

        if url_contains:
            requests = [r for r in requests if url_contains in r.url]

        return requests[-limit:]

    def get_unmatched_requests(self) -> List[MockRequest]:
        """Get requests that didn't match any rule."""
        return [r for r in self._requests if r.matched_rule is None]

    def get_rule_hits(self) -> Dict[str, int]:
        """Get hit counts for all rules."""
        return {
            rule.name: rule.hit_count
            for rule in self._rules.values()
        }

    def reset_hits(self) -> None:
        """Reset all hit counts."""
        for rule in self._rules.values():
            rule.hit_count = 0

    def clear_requests(self) -> None:
        """Clear recorded requests."""
        self._requests.clear()

    def remove_rule(
        self,
        rule_id: str,
    ) -> bool:
        """Remove a mock rule."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def clear_rules(self) -> None:
        """Clear all mock rules."""
        self._rules.clear()

    def verify_called(
        self,
        method: str,
        url_contains: str,
        times: Optional[int] = None,
    ) -> bool:
        """Verify a request was made."""
        matching = [
            r for r in self._requests
            if r.method == method.upper() and url_contains in r.url
        ]

        if times is not None:
            return len(matching) == times

        return len(matching) > 0

    def verify_not_called(
        self,
        method: str,
        url_contains: str,
    ) -> bool:
        """Verify a request was not made."""
        return self.verify_called(method, url_contains, times=0)

    def get_statistics(self) -> Dict[str, Any]:
        """Get mocker statistics."""
        total_rules = len(self._rules)
        active_rules = sum(1 for r in self._rules.values() if r.hit_count > 0)

        return {
            "total_rules": total_rules,
            "active_rules": active_rules,
            "total_requests": len(self._requests),
            "matched_requests": sum(1 for r in self._requests if r.matched_rule),
            "unmatched_requests": sum(1 for r in self._requests if not r.matched_rule),
        }

    def format_rule(self, rule: MockRule) -> str:
        """Format a rule for display."""
        lines = [
            "=" * 50,
            "  MOCK RULE",
            "=" * 50,
            "",
            f"  ID: {rule.rule_id}",
            f"  Name: {rule.name}",
            f"  Method: {rule.method}",
            f"  Pattern: {rule.url_pattern}",
            f"  Match Type: {rule.match_type.value}",
            f"  Priority: {rule.priority}",
            "",
            "-" * 50,
            "  RESPONSE",
            "-" * 50,
            f"  Status: {rule.response.status_code}",
            f"  Body: {rule.response.body}",
            f"  Delay: {rule.response.delay_ms}ms",
            "",
            f"  Hits: {rule.hit_count}",
            "",
            "=" * 50,
        ]

        return "\n".join(lines)

    def format_request(self, request: MockRequest) -> str:
        """Format a request for display."""
        matched = "✅" if request.matched_rule else "❌"

        lines = [
            "=" * 50,
            f"  {matched} MOCK REQUEST",
            "=" * 50,
            "",
            f"  Method: {request.method}",
            f"  URL: {request.url}",
            f"  Matched Rule: {request.matched_rule or 'None'}",
            f"  Time: {request.timestamp.strftime('%H:%M:%S')}",
            "",
        ]

        if request.headers:
            lines.append("-" * 50)
            lines.append("  HEADERS")
            lines.append("-" * 50)
            for key, value in request.headers.items():
                lines.append(f"  {key}: {value}")
            lines.append("")

        if request.body:
            lines.append("-" * 50)
            lines.append("  BODY")
            lines.append("-" * 50)
            lines.append(f"  {request.body}")
            lines.append("")

        lines.append("=" * 50)
        return "\n".join(lines)


def create_api_mocker(
    default_delay_ms: int = 0,
) -> APIMocker:
    """Create an API mocker instance."""
    return APIMocker(default_delay_ms=default_delay_ms)
