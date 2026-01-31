# TestAI Agent

> A cognitive QA system that surpasses human testing capabilities through precision context management and human-like interaction.

## Overview

TestAI Agent is an intelligent test generation system that:
- **Thinks Visibly** - Shows its reasoning process in real-time
- **Never Hallucinates** - Every test case traces to a knowledge base citation
- **Feels Human** - Asks clarifying questions, provides professional recommendations
- **Adapts to Audience** - Executive, Product, Engineering, and QA views

## Why This Beats Larger Models

Most QA automation tools stuff everything into one massive prompt. TestAI Agent takes a smarter approach:

| Traditional Approach | TestAI Agent |
|---------------------|--------------|
| 50k+ tokens per request | 3-5k tokens (focused) |
| Single expensive model | Multiple specialized models |
| Generic prompts | Task-specific prompts |
| No knowledge reuse | RAG-based knowledge retrieval |
| Black-box generation | Visible thinking with citations |
| Robot-like output | Human-like interaction |

**The result**: Better test cases at 1/10th the cost with full traceability.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the interactive demo
python human_demo.py

# Generate tests for a feature
python pipeline.py "Login Page" --stakeholder executive

# Run tests
python tests/run_tests.py
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Request                              │
│                    "Generate tests for login"                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Pipeline (Orchestration)                    │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  Parse   │─▶│  Query   │─▶│  Clarify │─▶│ Generate │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
│                                               │                  │
│                              ┌──────────┐  ┌──────────┐        │
│                              │Prioritize│◀─│  Format  │        │
│                              └──────────┘  └──────────┘        │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│     Brain       │  │     Cortex      │  │   Personality   │
│   (Knowledge)   │  │   (Reasoning)   │  │    (Human UX)   │
│                 │  │                 │  │                 │
│ • ChromaDB RAG  │  │ • Prioritizer   │  │ • Consultant    │
│ • Smart Ingest  │  │ • Confidence    │  │ • Clarifier     │
│ • Citations     │  │ • Reasoner      │  │ • Thinker       │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

## Key Features

### Zero Hallucination
Every test case cites its source:
```
📖 Source: Section 7.1: Email Validation (95% match)
```

### Visible Thinking
Watch the agent reason:
```
🤔 Understanding request: Login Page
🔍 Searching knowledge base for login rules...
📚 Found 12 relevant rules in Section 7
🧠 Cross-referencing security requirements...
⚖️ Deciding: Will generate 15 test cases (87% confidence)
✍️ Generating test cases with citations...
✅ Test generation complete
```

### Clarifying Questions
Before generating, the agent asks:
```
● Does your login support social authentication?
● What happens after 3-5 failed login attempts?
● Is multi-factor authentication enabled?
```

### Stakeholder Reports
Different views for different audiences:
- **Executive**: Ship decision, risk level, key metrics
- **Product**: Feature coverage, user impact
- **Engineering**: Technical details, implementation notes
- **QA**: Full test breakdown, step-by-step procedures

## Directory Structure

```
testai-agent/
├── brain/                 # Knowledge storage
│   ├── vector_store.py    # ChromaDB integration
│   └── smart_ingest.py    # Intelligent markdown parsing
│
├── cortex/                # Reasoning
│   ├── reasoner.py        # Citation-aware reasoning
│   ├── prioritizer.py     # Risk-based prioritization
│   └── confidence.py      # Confidence scoring
│
├── generators/            # Test generation
│   ├── cited_generator.py # Citation-first generation
│   ├── executive_summary.py # Stakeholder reports
│   └── report_generator.py # Report formatting
│
├── personality/           # Human-like behavior
│   ├── qa_consultant.py   # Consultant personality
│   ├── human_clarifier.py # Clarifying questions
│   └── thinker.py         # Thinking patterns
│
├── interface/             # User interface
│   ├── thinking_stream.py # Real-time thinking
│   ├── rich_output.py     # Beautiful terminal output
│   └── usage_dashboard.py # Usage tracking
│
├── conversation/          # Memory & persistence
│   ├── memory.py          # Conversational memory
│   └── persistence.py     # Session storage
│
├── connectors/            # LLM integration
│   └── llm_gateway.py     # Multi-provider gateway
│
├── pipeline.py            # End-to-end pipeline
├── human_demo.py          # Interactive demo
├── cli.py                 # Command-line interface
├── QA_BRAIN.md            # Knowledge base (200+ rules)
└── tests/                 # Test suite (35 tests)
```

## Usage Examples

### Interactive Demo
```bash
python human_demo.py
```

### Pipeline API
```python
from pipeline import TestPipeline
import asyncio

async def main():
    pipeline = TestPipeline()
    result = await pipeline.run(
        feature="Login Page",
        page_type="login",
        stakeholder="executive",
    )

    print(result.summary)
    print(f"Ship Decision: {result.ship_decision}")
    print(f"Tests Generated: {len(result.tests)}")

asyncio.run(main())
```

### CLI
```bash
# Generate tests with JSON output
python pipeline.py "Checkout Flow" -s engineering --json

# Run interactive session
python cli.py

# Show status
python main.py status
```

## Supported LLM Providers

| Provider | API Key Env Var | Best For |
|----------|-----------------|----------|
| **DeepSeek** | `DEEPSEEK_API_KEY` | Primary - Cost efficient |
| **OpenAI** | `OPENAI_API_KEY` | Classification, general tasks |
| **Anthropic** | `ANTHROPIC_API_KEY` | Security analysis, edge cases |
| **Google** | `GOOGLE_API_KEY` | Large context, fast tasks |

## Test Coverage

```
35/35 tests passing

Brain Tests:           2/2 ✅
Gateway Tests:         4/4 ✅
Cortex Tests:          3/3 ✅
Interface Tests:       3/3 ✅
Generators Tests:      3/3 ✅
Personality Tests:     2/2 ✅
Understanding Tests:   3/3 ✅
Integration Tests:     1/1 ✅
Enhanced Module Tests: 14/14 ✅
```

## Design Philosophy

### European Minimal Aesthetic
- Muted colors (slate, sage, warm tones)
- Clean, readable output
- Information disclosure on demand

### Human-Centric UX
- Think like a colleague, not a robot
- Ask before acting
- Explain reasoning
- Admit uncertainty

### Zero Hallucination
- Every claim has a source
- Every test has a citation
- Every decision has rationale

## Configuration

### Environment Variables
```bash
# Primary provider (recommended)
DEEPSEEK_API_KEY=sk-xxx

# Additional providers (optional)
OPENAI_API_KEY=sk-xxx
ANTHROPIC_API_KEY=sk-ant-xxx
GOOGLE_API_KEY=xxx
```

### API Limits
- DeepSeek: 10 calls per session
- OpenAI: 20 calls per session
- Claude: 20 calls per session
- Gemini: 30 calls per session

## Contributing

1. Run tests: `python tests/run_tests.py`
2. Follow the European design philosophy
3. Add citations for all generated content
4. Maintain human-like interaction patterns

## License

MIT

---

*Built with precision, designed for humans.*
