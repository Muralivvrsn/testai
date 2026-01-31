"""
TestAI Agent - Cognitive QA System

A production-ready QA agent that:
- Ingests feature specifications
- Retrieves exact testing rules from the Brain (RAG)
- Generates exhaustive test cases with citations
- Behaves like a Senior European QA Consultant

Usage:
    python -m testai_agent.main

Components:
    - Brain: Vector store for knowledge retrieval
    - Cortex: Reasoning engine for test generation
    - Gateway: Multi-provider LLM interface
"""

__version__ = "1.0.0"
__author__ = "TestAI"
