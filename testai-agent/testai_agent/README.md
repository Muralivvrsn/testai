# TestAI Agent - Cognitive QA System

A production-ready QA agent that behaves like a Senior European QA Consultant.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         main.py                              │
│               TestAIAgent (Orchestrator)                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │    Brain     │  │   Gateway    │  │   Cortex     │       │
│  │   (RAG)      │  │   (LLMs)     │  │  (Reasoning) │       │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤       │
│  │ ChromaDB     │  │ DeepSeek     │  │ Test Plans   │       │
│  │ Citations    │  │ OpenAI       │  │ Risk Assess  │       │
│  │ Sections     │  │ Anthropic    │  │ Citations    │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                     interface/cli.py                         │
│                   ConsoleUI (Rich CLI)                       │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.template .env
# Edit .env with your API key

# Run interactive mode
python -m testai_agent.main

# Run with a specific feature
python -m testai_agent.main "login page with email and password"
```

## Components

### Brain (brain/)
- **ingestion.py**: Parses QA_BRAIN.md with section-level tagging
- **vector_store.py**: ChromaDB-backed semantic search with citations

### Gateway (connectors/)
- **llm_gateway.py**: Multi-provider LLM support with usage tracking

### Cortex (core/)
- **cortex.py**: Reasoning engine that generates cited test plans

### Interface (interface/)
- **cli.py**: Rich console UI with colors, boxes, and progress indicators

## Commands

```
test <feature>    Generate test plan for a feature
analyze <feature> Analyze feature without generating tests
status            Show system status
help              Show help message
exit              Exit the application
```

## Example Output

```
🧪 > test login page

💭 Analyzing feature: login page...
💭 Retrieving relevant knowledge from Brain...
💭 Generating test cases with citations...

══════════════════════════════════════════════════════════
  📋 TEST PLAN: LOGIN PAGE
══════════════════════════════════════════════════════════

🎯 Risk Assessment
═══════════════════════════════════════════════════════════
  Feature: login page
  Overall Risk: High

  🔒 Security Risks:
     • SQL injection in email/password fields
     • Brute force attack vulnerability

📂 SECURITY TESTS (5)
───────────────────────────────────────────────────────────

  ┌─ TC-SEC-001: SQL injection in email field
  │  Category: Security
  │  Risk: 🔴 Critical
  │  Steps:
  │    1. Navigate to login page
  │    2. Enter ' OR '1'='1 in email field
  │    3. Submit form
  │  Expected: Login fails with generic error
  │  📚 Source: Section 7.1 - Email Validation
  └──────────────────────────────────────────────────────────
```

## Zero Hallucination Citation System

Every test case includes a source citation:
```
Source: Section {ID} - {Title}
```

Example: `Source: Section 7.1 - Email Validation`

This ensures every recommendation comes from the QA_BRAIN.md knowledge base.

## API Usage Limits

The system respects API limits (default: 10 calls for DeepSeek). Configure in .env:
```
MAX_LLM_CALLS=10
```

---
Version: 1.0.0
