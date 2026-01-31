"""
TestAI Agent - Knowledge Ingestion

Ingests QA_BRAIN.md into the vector store.
Run this once to load all QA knowledge.

Usage:
    python -m brain.ingest

Or from Python:
    from brain.ingest import ingest_qa_brain
    result = ingest_qa_brain("./QA_BRAIN.md")
"""

import sys
from pathlib import Path
from typing import Optional, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from brain.vector_store import QABrain, create_brain


def ingest_qa_brain(
    file_path: str = "./QA_BRAIN.md",
    persist_dir: str = "./.brain_data",
    force_reload: bool = False,
) -> Dict[str, Any]:
    """
    Ingest QA_BRAIN.md into the vector store.

    Args:
        file_path: Path to the QA brain markdown file
        persist_dir: Where to store the vector database
        force_reload: If True, re-ingest even if already loaded

    Returns:
        Status dictionary with ingestion results
    """
    print("🧠 Initializing QA Brain...")

    # Create brain instance
    brain = create_brain(persist_dir)

    # Check current status
    status = brain.get_status()
    if status["ready"] and not force_reload:
        print(f"✅ Brain already loaded with {status['knowledge_chunks']} chunks.")
        print("   Use force_reload=True to re-ingest.")
        return status

    # Find the QA_BRAIN.md file
    file_path = Path(file_path)

    if not file_path.exists():
        # Try common locations
        search_paths = [
            Path("./QA_BRAIN.md"),
            Path("../QA_BRAIN.md"),
            Path("../../QA_BRAIN.md"),
            Path(__file__).parent.parent / "QA_BRAIN.md",
            Path(__file__).parent.parent.parent / "QA_BRAIN.md",
        ]

        for sp in search_paths:
            if sp.exists():
                file_path = sp
                break

    if not file_path.exists():
        return {
            "status": "error",
            "message": f"Could not find QA_BRAIN.md. Searched: {file_path}",
        }

    print(f"📖 Loading knowledge from: {file_path}")

    # Ingest the file
    result = brain.ingest_knowledge(str(file_path), force_reload=force_reload)

    if result.get("status") == "success":
        print(f"✅ Successfully ingested {result.get('chunks', 0)} knowledge chunks!")
        print(f"   Categories: {result.get('categories', {})}")
    elif result.get("status") == "already_loaded":
        print(f"ℹ️  {result.get('message')}")
    else:
        print(f"❌ Error: {result.get('error', 'Unknown error')}")

    return result


def verify_brain(persist_dir: str = "./.brain_data") -> Dict[str, Any]:
    """
    Verify the brain is working by running test queries.

    Args:
        persist_dir: Brain storage location

    Returns:
        Verification results
    """
    print("\n🔍 Verifying brain...")

    brain = create_brain(persist_dir)

    if not brain.is_ready:
        return {
            "status": "not_ready",
            "message": "Brain is not loaded. Run ingest first.",
        }

    # Test queries
    test_queries = [
        ("login page validation", "login"),
        ("security testing XSS", "security"),
        ("edge cases for forms", "edge_case"),
        ("accessibility testing checklist", "accessibility"),
    ]

    results = []
    for query, expected_category in test_queries:
        search = brain.search(query, limit=3)
        found = len(search.chunks)
        confidence = search.confidence

        status = "✅" if found > 0 and confidence > 0.3 else "⚠️"
        print(f"  {status} Query: '{query}' → {found} results ({confidence:.0%} confidence)")

        results.append({
            "query": query,
            "found": found,
            "confidence": confidence,
        })

    avg_confidence = sum(r["confidence"] for r in results) / len(results)

    return {
        "status": "verified",
        "total_chunks": brain._chunk_count,
        "test_results": results,
        "average_confidence": avg_confidence,
        "message": f"Brain verified with {brain._chunk_count} chunks. Avg confidence: {avg_confidence:.0%}",
    }


def main():
    """Main entry point for CLI usage."""
    import argparse

    parser = argparse.ArgumentParser(description="Ingest QA knowledge into the brain")
    parser.add_argument(
        "--file",
        "-f",
        default="./QA_BRAIN.md",
        help="Path to QA_BRAIN.md file",
    )
    parser.add_argument(
        "--persist-dir",
        "-p",
        default="./.brain_data",
        help="Directory to store brain data",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-ingestion even if already loaded",
    )
    parser.add_argument(
        "--verify",
        "-v",
        action="store_true",
        help="Verify brain after ingestion",
    )

    args = parser.parse_args()

    # Run ingestion
    result = ingest_qa_brain(
        file_path=args.file,
        persist_dir=args.persist_dir,
        force_reload=args.force,
    )

    # Optionally verify
    if args.verify and result.get("status") in ["success", "already_loaded"]:
        verify_result = verify_brain(args.persist_dir)
        print(f"\n{verify_result.get('message')}")


if __name__ == "__main__":
    main()
