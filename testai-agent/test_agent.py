"""
TestAI Agent - Integration Test

Tests the complete agent flow with real API calls.
BUDGET: 10 calls max - use wisely!

Usage:
    python test_agent.py

This will:
1. Load the QA brain (no API call)
2. Make ONE API call to test generation
3. Report results
"""

import asyncio
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

# Track API usage
API_CALLS_MADE = 0
API_BUDGET = 10


def log_api_call(purpose: str):
    """Track API calls against budget."""
    global API_CALLS_MADE
    API_CALLS_MADE += 1
    print(f"📡 API Call #{API_CALLS_MADE}/{API_BUDGET}: {purpose}")
    if API_CALLS_MADE >= API_BUDGET:
        print("⚠️  Budget exhausted! No more API calls allowed.")


async def test_brain_only():
    """Test brain without API calls."""
    print("\n" + "=" * 60)
    print("TEST 1: Brain (Local Only - No API Calls)")
    print("=" * 60)

    from brain.vector_store import create_brain

    brain = create_brain("./.brain_data")
    status = brain.get_status()

    print(f"Brain ready: {status['ready']}")
    print(f"Knowledge chunks: {status['knowledge_chunks']}")

    if not status['ready']:
        print("\n⚠️  Brain not loaded. Attempting to ingest QA_BRAIN.md...")

        # Try to find QA_BRAIN.md
        search_paths = [
            Path("./QA_BRAIN.md"),
            Path("../QA_BRAIN.md"),
            Path("../../QA_BRAIN.md"),
        ]

        for path in search_paths:
            if path.exists():
                print(f"Found: {path}")
                result = brain.ingest_knowledge(str(path))
                print(f"Ingestion result: {result.get('status')}")
                if result.get('chunks'):
                    print(f"Loaded {result['chunks']} chunks")
                break
        else:
            print("Could not find QA_BRAIN.md")
            return False

    # Test search
    print("\n🔍 Testing brain search...")
    test_queries = [
        "login page validation rules",
        "security testing XSS injection",
        "edge cases for user input",
    ]

    for query in test_queries:
        result = brain.search(query, limit=3)
        print(f"  Query: '{query}' → {result.total_found} results ({result.confidence:.0%})")

    return True


async def test_gateway_only():
    """Test gateway with ONE API call."""
    print("\n" + "=" * 60)
    print("TEST 2: Gateway (ONE API Call)")
    print("=" * 60)

    from gateway.deepseek import create_deepseek_provider

    # DeepSeek API key from progress.md
    API_KEY = "sk-c104455631bb433b801fc4a16042419c"

    provider = create_deepseek_provider(
        api_key=API_KEY,
        model="deepseek-chat",
        temperature=0.3,
    )

    print(f"Provider: {provider.name}")
    print(f"Model: {provider.config.default_model}")
    print(f"Capabilities: {[c.value for c in provider.get_capabilities()]}")

    # Make ONE simple call to verify API works
    print("\n📡 Making API call...")
    log_api_call("Gateway test - simple completion")

    response = await provider.complete(
        prompt="List 3 test cases for a login page. Be brief.",
        system="You are a QA engineer. Be concise.",
        temperature=0.3,
        max_tokens=200,
    )

    print(f"\n✅ Response received:")
    print(f"   Tokens: {response.tokens_used}")
    print(f"   Cost: ${response.cost_estimate:.6f}")
    print(f"   Latency: {response.latency_ms:.0f}ms")
    print(f"\n   Content preview: {response.content[:200]}...")

    return response.finish_reason != "error"


async def test_full_generation():
    """Test full test generation (ONE API call)."""
    print("\n" + "=" * 60)
    print("TEST 3: Full Test Generation (ONE API Call)")
    print("=" * 60)

    global API_CALLS_MADE
    if API_CALLS_MADE >= API_BUDGET - 1:
        print("⚠️  Skipping - need to preserve API budget")
        return True

    from agent import create_agent

    API_KEY = "sk-c104455631bb433b801fc4a16042419c"

    agent = create_agent(
        api_key=API_KEY,
        brain_path="./.brain_data",
        budget_limit=0.10,  # $0.10 max for this test
    )

    # Check status
    status = agent.get_status()
    print(f"Agent Status:\n{status.summarize()}")

    # Generate tests for a simple login page
    print("\n📡 Generating tests for login page...")
    log_api_call("Full test generation - login page")

    sample_elements = [
        {"type": "input", "name": "email", "elementType": "input"},
        {"type": "input", "name": "password", "elementType": "input"},
        {"type": "button", "text": "Login", "elementType": "button"},
        {"type": "link", "text": "Forgot password?", "elementType": "link"},
    ]

    result = await agent.generate_tests(
        feature="User Login",
        page_type="login",
        elements=sample_elements,
        context="Simple login form with email and password",
    )

    print(f"\n✅ Generation Complete:")
    print(f"   Tests generated: {len(result.suite.tests)}")
    print(f"   Knowledge used: {result.knowledge_used} chunks")
    print(f"   Confidence: {result.confidence:.0%}")
    print(f"   Time: {result.generation_time_ms:.0f}ms")

    print(f"\n📋 Test Suite Summary:")
    print(result.suite.summarize())

    print(f"\n📝 Sample Tests:")
    for test in result.suite.tests[:3]:
        print(f"   - [{test.priority.value}] {test.title}")

    return len(result.suite.tests) > 0


async def run_tests():
    """Run all tests."""
    print("=" * 60)
    print("TestAI Agent - Integration Tests")
    print(f"API Budget: {API_BUDGET} calls")
    print("=" * 60)

    results = {}

    # Test 1: Brain (no API calls)
    try:
        results["brain"] = await test_brain_only()
    except Exception as e:
        print(f"❌ Brain test failed: {e}")
        results["brain"] = False

    # Test 2: Gateway (ONE API call)
    try:
        results["gateway"] = await test_gateway_only()
    except Exception as e:
        print(f"❌ Gateway test failed: {e}")
        results["gateway"] = False

    # Test 3: Full generation (ONE API call)
    try:
        results["generation"] = await test_full_generation()
    except Exception as e:
        print(f"❌ Generation test failed: {e}")
        import traceback
        traceback.print_exc()
        results["generation"] = False

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    for name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {name}: {status}")

    print(f"\n📊 API Calls Used: {API_CALLS_MADE}/{API_BUDGET}")
    print(f"📊 Remaining: {API_BUDGET - API_CALLS_MADE}")

    return all(results.values())


if __name__ == "__main__":
    success = asyncio.run(run_tests())
    sys.exit(0 if success else 1)
