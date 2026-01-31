---
active: true
iteration: 1
max_iterations: 1000
completion_promise: null
started_at: "2026-01-29T05:10:16Z"
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

Deliverable: Immediate generation of the full testai_agent/ directory structure and all necessary Python files (requirements.txt, .env template, source code) to make this runnable immediately. Focus on high-quality, documented, and robust code. dont' stop until tomorrow , run for 100hours and make sure that you run it unitl it will be real human , test it and update it properly, use any webpage or desktp app like electron and all, think before doing everything, we need to real teseting and don't waste too many credits on deepseek, test for all the things when you done with 1000 iterations and make the perfect picture test in the middel and make sure to behave like human QA, test in all the cases, please test properly and install everythign that you need. never compromise on quality, it is the most important thing, if something doesn't work, look and how do you make it work, please do that first, because quality and user experience are most important and don't waster single file or single line of use , use it 100% properly and remove if it is not requried at all. conver every category and cases as well, becasue we are the human QA which knows everything. test with ai, not just placholders, use environment env, venv and install all the things and test properly. all the functionality. create an interface like chat and add this agent so that we know how it works and test for real. and a real QA which has acess to consoles,network, cookies, storages as well.

Act as an Elite Principal Software Architect and Senior Human QA Specialist to iteratively engineer 'YaliTest', a production-grade autonomous QA platform designed to achieve 93% accuracy through a strict 'Input-Centric AI' philosophy. Your mandate is to build the complete, robust Python source code for the testai_agent directory, executing the provided 13-part strategy to create a system that outperforms human benchmarks by thinking before acting. You must implement a modular architecture featuring: a Vector Brain (ChromaDB/Qdrant) for precise RAG-based rule retrieval; a Model-Agnostic Gateway that intelligently routes tasks between DeepSeek (logic), Gemini (speed), and OpenAI (generation) based on cost/complexity; and a Stealth Playwright Worker Pool capable of recursive DOM extraction (piercing Shadow DOMs/Iframes) and anti-bot evasion. Behave like a real QA: implement 'Smart Waiting' to eliminate flakiness, a 'State Bank' for session persistence, 'The Reaper' for automated test data cleanup, and OS Keychain integration for security. You must ensure the agent possesses Human-in-the-Loop UX, proactively asking clarifying questions (via Slack/CLI) when confidence is low (<80%) and providing 'Risk Assessments' rather than just JSON. Do not stop at placeholders; generate self-healing code that produces Dry-Run Validated tests with full Playwright Traces for debugging, ensuring every line of code is production-ready, error-proofed, and optimized for a 100+ hour continuous regression cycle. build electron + playwright
remove unnesssry files and order struccture where it makes sense. I want you focus on frontend electron with the best minimal design of europe. update everytime and for each iterations if already existed, make it 10x better and more human, explanation, speaking, all should be human. Aesthetic: Ultra-clean "Linear-style" app interface design. The scene features floating UI elements with deeply rounded corners (pill shapes) and soft, diffuse drop shadows to create elevation.

Color & Material: A monochromatic off-white palette (#FAFAFA) with matte finishes. High-contrast black typography. A single, vibrant accent color is used sparingly to guide the eye. before implemnting test it properly and make the gaps fill and make a humanoid senior QA agent, we should have the intellengece of the brain of a senior QA agent check properly everything, form 0 to 1.