"""
TestAI Agent - Dashboard Module

Web-based dashboard for test generation and visualization.
"""

from .server import DashboardServer, run_dashboard

__all__ = [
    "DashboardServer",
    "run_dashboard",
]
