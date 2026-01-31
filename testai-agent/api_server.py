#!/usr/bin/env python3
"""
TestAI Agent - API Server

A simple HTTP API for programmatic test generation.
Enables integration with other tools, CI/CD pipelines, and web interfaces.

Endpoints:
- POST /generate - Generate tests for a feature
- GET /health - Health check
- GET /status - System status
- POST /export - Export tests in various formats

Usage:
    python api_server.py                    # Start on port 8080
    python api_server.py --port 3000        # Custom port
"""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from pipeline import TestPipeline, PipelineResult
from generators.cited_generator import create_generator_for_page_type
from generators.test_data import create_test_data_generator, InputType
from executors import create_executor, OutputFormat


# ─────────────────────────────────────────────────────────────────
# API Response Helpers
# ─────────────────────────────────────────────────────────────────

def success_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a success response."""
    return {
        "success": True,
        "timestamp": datetime.now().isoformat(),
        "data": data,
    }


def error_response(message: str, code: int = 400) -> Dict[str, Any]:
    """Create an error response."""
    return {
        "success": False,
        "timestamp": datetime.now().isoformat(),
        "error": {
            "code": code,
            "message": message,
        },
    }


# ─────────────────────────────────────────────────────────────────
# API Handler
# ─────────────────────────────────────────────────────────────────

class TestAIRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for TestAI API."""

    # Shared pipeline (created lazily)
    _pipeline: Optional[TestPipeline] = None
    _executor = None
    _test_data_gen = None

    @classmethod
    def get_pipeline(cls) -> TestPipeline:
        """Get or create the pipeline."""
        if cls._pipeline is None:
            cls._pipeline = TestPipeline(verbose=False)
        return cls._pipeline

    @classmethod
    def get_executor(cls):
        """Get or create the executor."""
        if cls._executor is None:
            cls._executor = create_executor()
        return cls._executor

    @classmethod
    def get_test_data_generator(cls):
        """Get or create the test data generator."""
        if cls._test_data_gen is None:
            cls._test_data_gen = create_test_data_generator()
        return cls._test_data_gen

    def _send_json(self, data: Dict[str, Any], status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2, default=str).encode())

    def _read_body(self) -> Dict[str, Any]:
        """Read and parse JSON body."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        body = self.rfile.read(content_length).decode()
        return json.loads(body) if body else {}

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            self._handle_health()
        elif path == "/status":
            self._handle_status()
        elif path == "/page-types":
            self._handle_page_types()
        elif path == "/input-types":
            self._handle_input_types()
        else:
            self._send_json(error_response(f"Unknown endpoint: {path}", 404), 404)

    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_body()

            if path == "/generate":
                self._handle_generate(body)
            elif path == "/export":
                self._handle_export(body)
            elif path == "/test-data":
                self._handle_test_data(body)
            else:
                self._send_json(error_response(f"Unknown endpoint: {path}", 404), 404)

        except json.JSONDecodeError:
            self._send_json(error_response("Invalid JSON body"), 400)
        except Exception as e:
            self._send_json(error_response(str(e), 500), 500)

    def _handle_health(self):
        """Handle health check."""
        self._send_json(success_response({
            "status": "healthy",
            "service": "testai-agent",
            "version": "1.0.0",
        }))

    def _handle_status(self):
        """Handle status check."""
        pipeline = self.get_pipeline()

        self._send_json(success_response({
            "pipeline_ready": True,
            "supported_page_types": [
                "login", "signup", "checkout", "search", "profile",
            ],
            "supported_stakeholders": [
                "executive", "product", "engineering", "qa",
            ],
            "export_formats": [
                "json", "pytest", "typescript",
            ],
        }))

    def _handle_page_types(self):
        """Return available page types."""
        self._send_json(success_response({
            "page_types": [
                {"id": "login", "name": "Login Page", "sections": "7.x"},
                {"id": "signup", "name": "Signup/Registration", "sections": "8.x"},
                {"id": "checkout", "name": "Checkout/Payment", "sections": "9.x"},
                {"id": "search", "name": "Search", "sections": "10.x"},
                {"id": "profile", "name": "Profile/Settings", "sections": "11.x"},
                {"id": "form", "name": "Generic Form", "sections": "1-3.x"},
            ]
        }))

    def _handle_input_types(self):
        """Return available input types for test data."""
        self._send_json(success_response({
            "input_types": [
                {"id": "email", "name": "Email Address"},
                {"id": "password", "name": "Password"},
                {"id": "username", "name": "Username"},
                {"id": "name", "name": "Name"},
                {"id": "phone", "name": "Phone Number"},
                {"id": "address", "name": "Address"},
                {"id": "credit_card", "name": "Credit Card"},
                {"id": "cvv", "name": "CVV"},
                {"id": "expiry", "name": "Card Expiry"},
                {"id": "date", "name": "Date"},
                {"id": "number", "name": "Number"},
                {"id": "url", "name": "URL"},
                {"id": "text", "name": "Text"},
                {"id": "search", "name": "Search Query"},
            ]
        }))

    def _handle_generate(self, body: Dict[str, Any]):
        """Handle test generation request."""
        feature = body.get("feature")
        if not feature:
            self._send_json(error_response("Missing 'feature' in request body"), 400)
            return

        page_type = body.get("page_type")
        stakeholder = body.get("stakeholder", "executive")
        max_tests = body.get("max_tests", 20)
        skip_clarify = body.get("skip_clarify", True)

        # Run pipeline
        pipeline = self.get_pipeline()

        # Create event loop for async
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            result = loop.run_until_complete(
                pipeline.run(
                    feature=feature,
                    page_type=page_type,
                    stakeholder=stakeholder,
                    skip_clarify=skip_clarify,
                    max_tests=max_tests,
                )
            )

            self._send_json(success_response({
                "feature": feature,
                "page_type": result.context.page_type,
                "stakeholder": stakeholder,
                "ship_decision": result.ship_decision,
                "risk_level": result.risk_level,
                "test_count": len(result.tests),
                "citations": result.citations,
                "execution_time_ms": result.execution_time * 1000,
                "phases_completed": result.phases_completed,
                "tests": result.tests,
                "summary": result.summary,
            }))

        finally:
            loop.close()

    def _handle_export(self, body: Dict[str, Any]):
        """Handle test export request."""
        tests = body.get("tests", [])
        format_type = body.get("format", "json")
        feature = body.get("feature", "Tests")

        if not tests:
            self._send_json(error_response("Missing 'tests' in request body"), 400)
            return

        executor = self.get_executor()

        if format_type == "json":
            self._send_json(success_response({
                "format": "json",
                "content": tests,
            }))

        elif format_type in ["pytest", "python"]:
            from executors import generate_pytest_suite
            code = generate_pytest_suite(tests, f"test_{feature.lower().replace(' ', '_')}")
            self._send_json(success_response({
                "format": "pytest",
                "content": code,
            }))

        elif format_type in ["typescript", "ts"]:
            code_parts = []
            for test in tests:
                code_parts.append(executor.generate_code(test, OutputFormat.TYPESCRIPT))
            self._send_json(success_response({
                "format": "typescript",
                "content": "\n\n".join(code_parts),
            }))

        else:
            self._send_json(error_response(f"Unknown format: {format_type}"), 400)

    def _handle_test_data(self, body: Dict[str, Any]):
        """Handle test data generation request."""
        input_type = body.get("input_type")
        form_fields = body.get("form_fields")
        include_security = body.get("include_security", True)

        generator = self.get_test_data_generator()

        if form_fields:
            # Generate for a form
            fields = {}
            for field_name, field_type in form_fields.items():
                try:
                    fields[field_name] = InputType(field_type)
                except ValueError:
                    self._send_json(error_response(f"Unknown input type: {field_type}"), 400)
                    return

            form_data = generator.generate_for_form(fields, include_security)

            result = {}
            for field_name, data_set in form_data.items():
                result[field_name] = {
                    "valid": [{"value": i.value, "description": i.description} for i in data_set.get_valid()],
                    "invalid": [{"value": i.value, "description": i.description} for i in data_set.get_invalid()],
                    "edge_cases": [{"value": i.value, "description": i.description} for i in data_set.get_edge_cases()],
                    "security": [{"value": i.value, "description": i.description} for i in data_set.get_security()],
                }

            self._send_json(success_response(result))

        elif input_type:
            # Generate for a single input type
            try:
                it = InputType(input_type)
            except ValueError:
                self._send_json(error_response(f"Unknown input type: {input_type}"), 400)
                return

            data_set = generator.generate(it)

            self._send_json(success_response({
                "input_type": input_type,
                "valid": [{"value": i.value, "description": i.description} for i in data_set.get_valid()],
                "invalid": [{"value": i.value, "description": i.description} for i in data_set.get_invalid()],
                "edge_cases": [{"value": i.value, "description": i.description} for i in data_set.get_edge_cases()],
                "security": [{"value": i.value, "description": i.description} for i in data_set.get_security()],
            }))

        else:
            self._send_json(error_response("Provide 'input_type' or 'form_fields'"), 400)

    def log_message(self, format, *args):
        """Custom logging format."""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")


# ─────────────────────────────────────────────────────────────────
# Server
# ─────────────────────────────────────────────────────────────────

def run_server(port: int = 8080):
    """Run the API server."""
    server = HTTPServer(("0.0.0.0", port), TestAIRequestHandler)

    print("=" * 55)
    print("  TestAI Agent - API Server")
    print("=" * 55)
    print(f"\n  Running on http://localhost:{port}")
    print("\n  Endpoints:")
    print("    GET  /health      - Health check")
    print("    GET  /status      - System status")
    print("    GET  /page-types  - Available page types")
    print("    GET  /input-types - Available input types")
    print("    POST /generate    - Generate tests")
    print("    POST /export      - Export tests")
    print("    POST /test-data   - Generate test data")
    print("\n  Press Ctrl+C to stop\n")
    print("=" * 55)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\nShutting down server...")
        server.shutdown()


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="TestAI Agent API Server")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Port to run on")

    args = parser.parse_args()
    run_server(args.port)


if __name__ == "__main__":
    main()
