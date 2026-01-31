"""
TestAI Agent - API Client

HTTP client for API testing with request/response
tracking, retry logic, and response validation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import uuid
import time


class HTTPMethod(Enum):
    """HTTP methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ContentType(Enum):
    """Content types."""
    JSON = "application/json"
    XML = "application/xml"
    FORM = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    TEXT = "text/plain"
    HTML = "text/html"


@dataclass
class APIRequest:
    """An API request."""
    request_id: str
    method: HTTPMethod
    url: str
    headers: Dict[str, str]
    body: Optional[Any]
    params: Dict[str, str]
    timeout_ms: int
    created_at: datetime


@dataclass
class APIResponse:
    """An API response."""
    response_id: str
    request_id: str
    status_code: int
    headers: Dict[str, str]
    body: Any
    duration_ms: float
    received_at: datetime
    error: Optional[str] = None


@dataclass
class RequestHistory:
    """History entry for a request/response pair."""
    request: APIRequest
    response: APIResponse


class APIClient:
    """
    API testing client.

    Features:
    - Request building
    - Response validation
    - Request history
    - Retry logic
    - Authentication
    """

    # Default timeout
    DEFAULT_TIMEOUT_MS = 30000

    # Common status codes
    SUCCESS_CODES = {200, 201, 202, 204}
    REDIRECT_CODES = {301, 302, 303, 307, 308}
    CLIENT_ERROR_CODES = range(400, 500)
    SERVER_ERROR_CODES = range(500, 600)

    def __init__(
        self,
        base_url: str = "",
        default_headers: Optional[Dict[str, str]] = None,
        timeout_ms: int = 30000,
        retry_count: int = 0,
        retry_delay_ms: int = 1000,
    ):
        """Initialize the client."""
        self._base_url = base_url.rstrip("/")
        self._default_headers = default_headers or {}
        self._timeout_ms = timeout_ms
        self._retry_count = retry_count
        self._retry_delay_ms = retry_delay_ms

        self._history: List[RequestHistory] = []
        self._auth_header: Optional[str] = None
        self._interceptors: List[Callable] = []

        self._request_counter = 0
        self._response_counter = 0

        # Simulated responses for testing
        self._mock_responses: Dict[str, Dict[str, Any]] = {}

    def set_auth_token(
        self,
        token: str,
        token_type: str = "Bearer",
    ) -> None:
        """Set authentication token."""
        self._auth_header = f"{token_type} {token}"
        self._default_headers["Authorization"] = self._auth_header

    def set_api_key(
        self,
        api_key: str,
        header_name: str = "X-API-Key",
    ) -> None:
        """Set API key authentication."""
        self._default_headers[header_name] = api_key

    def set_basic_auth(
        self,
        username: str,
        password: str,
    ) -> None:
        """Set basic authentication."""
        import base64
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._auth_header = f"Basic {credentials}"
        self._default_headers["Authorization"] = self._auth_header

    def add_interceptor(
        self,
        interceptor: Callable[[APIRequest], APIRequest],
    ) -> None:
        """Add a request interceptor."""
        self._interceptors.append(interceptor)

    def mock_response(
        self,
        url_pattern: str,
        method: HTTPMethod,
        status_code: int,
        body: Any,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Set up a mock response for testing."""
        key = f"{method.value}:{url_pattern}"
        self._mock_responses[key] = {
            "status_code": status_code,
            "body": body,
            "headers": headers or {},
        }

    def request(
        self,
        method: HTTPMethod,
        path: str,
        body: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout_ms: Optional[int] = None,
    ) -> APIResponse:
        """Make an API request."""
        self._request_counter += 1
        request_id = f"REQ-{self._request_counter:05d}"

        url = f"{self._base_url}/{path.lstrip('/')}" if self._base_url else path

        # Merge headers
        all_headers = {**self._default_headers, **(headers or {})}

        # Add content type if body present
        if body and "Content-Type" not in all_headers:
            all_headers["Content-Type"] = ContentType.JSON.value

        request = APIRequest(
            request_id=request_id,
            method=method,
            url=url,
            headers=all_headers,
            body=body,
            params=params or {},
            timeout_ms=timeout_ms or self._timeout_ms,
            created_at=datetime.now(),
        )

        # Apply interceptors
        for interceptor in self._interceptors:
            request = interceptor(request)

        # Execute with retry
        response = self._execute_with_retry(request)

        # Store in history
        self._history.append(RequestHistory(request=request, response=response))

        return response

    def _execute_with_retry(
        self,
        request: APIRequest,
    ) -> APIResponse:
        """Execute request with retry logic."""
        last_error = None
        attempts = 0

        while attempts <= self._retry_count:
            try:
                response = self._execute(request)

                # Check if retry needed (server errors)
                if response.status_code in self.SERVER_ERROR_CODES and attempts < self._retry_count:
                    attempts += 1
                    time.sleep(self._retry_delay_ms / 1000)
                    continue

                return response

            except Exception as e:
                last_error = str(e)
                attempts += 1

                if attempts <= self._retry_count:
                    time.sleep(self._retry_delay_ms / 1000)

        # Return error response
        self._response_counter += 1
        return APIResponse(
            response_id=f"RES-{self._response_counter:05d}",
            request_id=request.request_id,
            status_code=0,
            headers={},
            body=None,
            duration_ms=0,
            received_at=datetime.now(),
            error=last_error or "Request failed",
        )

    def _execute(
        self,
        request: APIRequest,
    ) -> APIResponse:
        """Execute a single request (simulated for testing)."""
        self._response_counter += 1
        response_id = f"RES-{self._response_counter:05d}"

        start_time = datetime.now()

        # Check for mock response
        mock_key = f"{request.method.value}:{request.url}"
        for pattern, mock in self._mock_responses.items():
            if pattern in mock_key or mock_key.endswith(pattern.split(":")[-1]):
                return APIResponse(
                    response_id=response_id,
                    request_id=request.request_id,
                    status_code=mock["status_code"],
                    headers=mock["headers"],
                    body=mock["body"],
                    duration_ms=10.0,  # Simulated fast response
                    received_at=datetime.now(),
                )

        # Default simulated response
        end_time = datetime.now()
        duration_ms = (end_time - start_time).total_seconds() * 1000 + 50

        return APIResponse(
            response_id=response_id,
            request_id=request.request_id,
            status_code=200,
            headers={"Content-Type": ContentType.JSON.value},
            body={"success": True, "message": "OK"},
            duration_ms=duration_ms,
            received_at=datetime.now(),
        )

    def get(
        self,
        path: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> APIResponse:
        """Make a GET request."""
        return self.request(HTTPMethod.GET, path, params=params, headers=headers)

    def post(
        self,
        path: str,
        body: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> APIResponse:
        """Make a POST request."""
        return self.request(HTTPMethod.POST, path, body=body, headers=headers)

    def put(
        self,
        path: str,
        body: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> APIResponse:
        """Make a PUT request."""
        return self.request(HTTPMethod.PUT, path, body=body, headers=headers)

    def patch(
        self,
        path: str,
        body: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> APIResponse:
        """Make a PATCH request."""
        return self.request(HTTPMethod.PATCH, path, body=body, headers=headers)

    def delete(
        self,
        path: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> APIResponse:
        """Make a DELETE request."""
        return self.request(HTTPMethod.DELETE, path, headers=headers)

    def assert_status(
        self,
        response: APIResponse,
        expected_status: int,
    ) -> bool:
        """Assert response status code."""
        return response.status_code == expected_status

    def assert_success(
        self,
        response: APIResponse,
    ) -> bool:
        """Assert response is successful."""
        return response.status_code in self.SUCCESS_CODES

    def assert_body_contains(
        self,
        response: APIResponse,
        key: str,
        value: Any = None,
    ) -> bool:
        """Assert response body contains key (and optionally value)."""
        if not isinstance(response.body, dict):
            return False

        if key not in response.body:
            return False

        if value is not None:
            return response.body[key] == value

        return True

    def assert_header(
        self,
        response: APIResponse,
        header_name: str,
        expected_value: Optional[str] = None,
    ) -> bool:
        """Assert response has header."""
        header_value = response.headers.get(header_name)

        if header_value is None:
            return False

        if expected_value is not None:
            return header_value == expected_value

        return True

    def get_history(
        self,
        limit: int = 20,
    ) -> List[RequestHistory]:
        """Get request history."""
        return self._history[-limit:]

    def clear_history(self) -> None:
        """Clear request history."""
        self._history.clear()

    def get_statistics(self) -> Dict[str, Any]:
        """Get client statistics."""
        if not self._history:
            return {
                "total_requests": 0,
                "success_rate": 0,
                "avg_duration_ms": 0,
            }

        success_count = sum(
            1 for h in self._history
            if h.response.status_code in self.SUCCESS_CODES
        )

        total_duration = sum(h.response.duration_ms for h in self._history)

        return {
            "total_requests": len(self._history),
            "success_rate": success_count / len(self._history),
            "avg_duration_ms": total_duration / len(self._history),
            "error_count": sum(1 for h in self._history if h.response.error),
        }

    def format_request(self, request: APIRequest) -> str:
        """Format a request for display."""
        lines = [
            "=" * 50,
            "  API REQUEST",
            "=" * 50,
            "",
            f"  {request.method.value} {request.url}",
            "",
            "-" * 50,
            "  HEADERS",
            "-" * 50,
        ]

        for key, value in request.headers.items():
            lines.append(f"  {key}: {value}")

        if request.body:
            lines.extend([
                "",
                "-" * 50,
                "  BODY",
                "-" * 50,
                f"  {request.body}",
            ])

        lines.extend(["", "=" * 50])
        return "\n".join(lines)

    def format_response(self, response: APIResponse) -> str:
        """Format a response for display."""
        status_emoji = "✅" if response.status_code in self.SUCCESS_CODES else "❌"

        lines = [
            "=" * 50,
            f"  {status_emoji} API RESPONSE",
            "=" * 50,
            "",
            f"  Status: {response.status_code}",
            f"  Duration: {response.duration_ms:.0f}ms",
            "",
        ]

        if response.error:
            lines.append(f"  Error: {response.error}")
            lines.append("")

        lines.append("-" * 50)
        lines.append("  HEADERS")
        lines.append("-" * 50)

        for key, value in response.headers.items():
            lines.append(f"  {key}: {value}")

        if response.body:
            lines.extend([
                "",
                "-" * 50,
                "  BODY",
                "-" * 50,
                f"  {response.body}",
            ])

        lines.extend(["", "=" * 50])
        return "\n".join(lines)


def create_api_client(
    base_url: str = "",
    default_headers: Optional[Dict[str, str]] = None,
    timeout_ms: int = 30000,
    retry_count: int = 0,
) -> APIClient:
    """Create an API client instance."""
    return APIClient(
        base_url=base_url,
        default_headers=default_headers,
        timeout_ms=timeout_ms,
        retry_count=retry_count,
    )
