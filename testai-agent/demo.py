#!/usr/bin/env python3
"""
TestAI Agent - Comprehensive Demo

Demonstrates the full cognitive QA system with:
- Human-like personality and thinking
- Brain (RAG) knowledge retrieval
- Test plan generation with citations
- Executive report output

Usage:
    python demo.py [feature]
    
Examples:
    python demo.py "login page"
    python demo.py "checkout with payment"
"""

import asyncio
import sys
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from testai_agent.brain.vector_store import QABrain
from testai_agent.connectors.llm_gateway import LLMGateway, DeepSeekConnector
from testai_agent.core.cortex import create_cortex
from testai_agent.core.personality import QAConsultantPersonality, ThinkingPhase, get_questions_for_feature
from testai_agent.core.memory import SessionMemory
from testai_agent.core.report import ReportGenerator
from testai_agent.interface.cli import ConsoleUI, Colors, c


async def run_demo(feature: str):
    """Run a full demo of the TestAI Agent."""
    
    ui = ConsoleUI()
    
    # Print header
    print(c("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   🧪  TestAI Agent - Cognitive QA Demo                          ║
║   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                           ║
║   Senior European QA Consultant: Alex                            ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""", Colors.BRIGHT_CYAN))
    
    # Initialize session memory
    print(c("Initializing session...", Colors.DIM))
    memory = SessionMemory(storage_dir='/tmp/claude/testai_session')
    memory.add_user_message(f"Generate test plan for: {feature}")
    
    # Initialize Brain
    print(c("Loading QA knowledge base...", Colors.DIM))
    brain = QABrain(persist_directory='/tmp/claude/qa_brain_demo')
    
    if not brain.is_ready:
        brain_file = Path(__file__).parent / "QA_BRAIN.md"
        if brain_file.exists():
            result = brain.ingest(str(brain_file))
            print(c(f"  ✓ Loaded {result.get('chunks', 0)} knowledge chunks", Colors.GREEN))
        else:
            print(c(f"  ✗ QA_BRAIN.md not found", Colors.RED))
            return
    else:
        status = brain.get_status()
        print(c(f"  ✓ Brain ready with {status['knowledge_chunks']} chunks", Colors.GREEN))
    
    # Initialize Gateway
    print(c("Connecting to LLM Gateway...", Colors.DIM))
    gateway = LLMGateway()
    gateway.add_provider(DeepSeekConnector(
        api_key='sk-c104455631bb433b801fc4a16042419c',
        model='deepseek-chat',
        max_calls=5
    ))
    print(c("  ✓ DeepSeek connected", Colors.GREEN))
    
    # Initialize Cortex with visible thinking
    thinking_lines = []
    def thinking_callback(thought):
        thinking_lines.append(thought)
        print(c(f"  💭 {thought}", Colors.DIM, Colors.ITALIC))
    
    cortex = create_cortex(brain, gateway, thinking_callback)
    
    print()
    print(c("=" * 60, Colors.DIM))
    print()
    
    # Show human-like introduction
    intro = QAConsultantPersonality.get_thinking(ThinkingPhase.UNDERSTANDING, feature=feature)
    print(c(f"🧑‍💼 Alex: {intro}", Colors.WHITE))
    print()
    
    # Check for clarifying questions
    print(c("Checking if clarification is needed...", Colors.DIM))
    analysis = await cortex.analyze_feature(feature)
    page_type = analysis.get('page_type', 'general')
    
    questions = get_questions_for_feature(page_type)
    if questions:
        print()
        print(c(f"🧑‍💼 Alex: {QAConsultantPersonality.get_clarification_intro()}", Colors.WHITE))
        print()
        for q in questions[:2]:  # Show first 2 questions
            print(c(f"   ❓ {q['question']}", Colors.YELLOW))
            for i, opt in enumerate(q['options'], 1):
                print(c(f"      {i}. {opt}", Colors.DIM))
            print()
        print(c("   (In production, I would wait for your answers)", Colors.DIM))
    
    print()
    print(c("=" * 60, Colors.DIM))
    print()
    
    # Retrieve relevant knowledge
    print(c("🧑‍💼 Alex: Let me consult my knowledge base...", Colors.WHITE))
    print()
    
    result = brain.retrieve_for_feature(feature)
    print(c(f"   Found {result.total_found} relevant knowledge items", Colors.DIM))
    print(c(f"   Confidence: {result.confidence:.0%}", Colors.DIM))
    print()
    
    # Show what sections are being consulted
    sections_seen = set()
    for k in result.knowledge[:5]:
        if k.section_id not in sections_seen:
            sections_seen.add(k.section_id)
            consulting = QAConsultantPersonality.get_thinking(
                ThinkingPhase.CONSULTING,
                section=k.section_id,
                title=k.section_title
            )
            print(c(f"  💭 {consulting}", Colors.DIM, Colors.ITALIC))
    
    print()
    print(c("=" * 60, Colors.DIM))
    print()
    
    # Generate test plan
    print(c("🧑‍💼 Alex: Generating comprehensive test plan...", Colors.WHITE))
    print()
    
    try:
        test_plan = await cortex.generate_test_plan(feature)
        
        # Generate executive summary
        summary = ReportGenerator.generate_executive_summary(test_plan, result.confidence)
        
        # Print executive summary
        print(c("=" * 60, Colors.BRIGHT_CYAN))
        print(c("  📊 EXECUTIVE SUMMARY", Colors.BOLD, Colors.BRIGHT_CYAN))
        print(c("=" * 60, Colors.BRIGHT_CYAN))
        print()
        
        # Risk level with color
        risk_colors = {
            "Critical": Colors.BRIGHT_RED,
            "High": Colors.RED,
            "Medium": Colors.YELLOW,
            "Low": Colors.GREEN
        }
        risk_color = risk_colors.get(summary.overall_risk, Colors.WHITE)
        
        print(f"  Feature:              {summary.feature}")
        print(f"  Overall Risk:         {c(summary.overall_risk, risk_color, Colors.BOLD)}")
        print(f"  Total Test Cases:     {summary.test_count}")
        print(f"  Critical Priority:    {c(str(summary.critical_tests), Colors.RED)}")
        print(f"  High Priority:        {c(str(summary.high_tests), Colors.YELLOW)}")
        print(f"  Estimated Effort:     {summary.estimated_effort}")
        print(f"  Confidence Level:     {summary.confidence_level}")
        print()
        
        print(c("  Key Findings:", Colors.BOLD))
        for finding in summary.key_findings:
            print(f"    ⚠️  {finding}")
        print()
        
        print(c("  Recommendations:", Colors.BOLD))
        for i, rec in enumerate(summary.recommendations, 1):
            print(f"    {i}. {rec}")
        print()
        
        # Print test plan
        ui.print_test_plan(test_plan)
        
        # Save session
        memory.add_generated_plan(
            feature=feature,
            test_count=test_plan.total_tests,
            risk_level=summary.overall_risk,
            summary=f"Generated {test_plan.total_tests} tests with {summary.critical_tests} critical"
        )
        memory.add_assistant_message(f"Generated {test_plan.total_tests} test cases")
        
        # Final conclusion
        conclusion = QAConsultantPersonality.get_conclusion(test_plan.total_tests)
        print()
        print(c(f"🧑‍💼 Alex: {conclusion}", Colors.WHITE))
        print()
        
        # Session stats
        stats = memory.get_stats()
        print(c("Session Statistics:", Colors.DIM))
        print(c(f"  Session: {stats['session_id']}", Colors.DIM))
        print(c(f"  Total tests generated this session: {stats['total_tests_generated']}", Colors.DIM))
        
        print()
        print(c("=" * 60, Colors.BRIGHT_CYAN))
        print(c("  Demo Complete - TestAI Agent Ready for Production", Colors.BOLD, Colors.GREEN))
        print(c("=" * 60, Colors.BRIGHT_CYAN))
        
    except Exception as e:
        print(c(f"  ✗ Error generating test plan: {e}", Colors.RED))
        import traceback
        traceback.print_exc()


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        feature = " ".join(sys.argv[1:])
    else:
        feature = "login page with email and password"
        print(f"No feature specified, using default: '{feature}'")
        print("Usage: python demo.py 'your feature description'")
        print()
    
    asyncio.run(run_demo(feature))


if __name__ == "__main__":
    main()
