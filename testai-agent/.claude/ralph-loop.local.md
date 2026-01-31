---
active: true
iteration: 18
max_iterations: 1000
completion_promise: null
started_at: "2026-01-28T19:06:54Z"
---

Act as an Elite Principal Software Architect and UX Specialist.

I need you to build the complete, production-ready source code for the 'TestAI Agent'—a cognitive QA system designed to surpass human testing capabilities and outperform massive models like Opus through precision context management.

Core Objective: Create a modular, Python-based agent in a folder named testai_agent that performs one core function: ingesting specific feature specifications (e.g., Login Page), retrieving the exact testing rules from a vector-based 'Brain' (eliminating context window limits), and deterministically generating exhaustive test cases across Security, UI, and Functional categories.

Required Implementation:

The Brain (Memory): Write brain/ingestion.py and brain/vector_store.py using ChromaDB or Qdrant. It must parse a markdown file (QA_BRAIN.md), split it by sections (e.g., Input Validation, Security), and tag them for precise retrieval (RAG).

The Cortex (Reasoning): Write core/cortex.py using a model-agnostic gateway. Implement the logic to query the 'Brain' for rules relevant only to the user's input, then use an LLM to generate the test plan.

The Gateway (Model Agnostic): Write connectors/llm_gateway.py to support switching between DeepSeek (use my key: sk-c104455631bb433b801fc4a16042419c), OpenAI, Claude, and Gemini. Implement strict error handling and usage limits (max 10 calls for DeepSeek).

The Interface (UX): Write main.py as a CLI that behaves like a Senior European QA Consultant. It must not just output JSON; it should use rich text (Markdown) to present a Risk Assessment, ask clarifying questions if the input is vague (like a real human), and present the Test Plan in a beautiful, structured format.

Progress Tracking: Initialize a PROGRESS.md file that dynamically tracks what capabilities are online (e.g., RAG: Active, Execution: Pending) and what research is needed next to beat human benchmarks.

Design Philosophy:

Zero Hallucination: The agent must explicitly cite which section of the Brain it used to generate a test case (e.g., Source: Section 7.1 - Email Validation).

Human-Centric UX: The agent should think visible to the user (e.g., Consulting security protocols...), ask for clarification before generating, and structure its output to be read by executives, not just machines.

Scalability: The architecture must be ready to plug in Playwright for execution later, but for now, focus on the reasoning and planning layer.

Deliverable: Immediate generation of the full testai_agent/ directory structure and all necessary Python files (requirements.txt, .env template, source code) to make this runnable immediately. Focus on high-quality, documented, and robust code. dont' stop until tomorrow , run for 100hours and make sure that you run it unitl it will be real human 
