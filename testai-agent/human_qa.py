#!/usr/bin/env python3
"""
Human QA Agent - Acts Like a Real Senior QA Engineer

Not a formal assistant - a REAL QA colleague who:
- Talks naturally, like a friend who happens to be amazing at QA
- Remembers your conversation and project context
- Thinks about edge cases automatically
- Asks smart questions, not bureaucratic ones
- Gets straight to the point

Usage:
    python human_qa.py

    > hi
    Hey! What are we breaking today? 😄

    > need to test login
    Alright, login page - my favorite hunting ground.
    Let me think through the attack vectors...
    [Generates tests naturally]
"""

import asyncio
import sys
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

sys.path.insert(0, str(Path(__file__).parent))

from gateway.base import Message
from gateway.deepseek import DeepSeekProvider, ProviderConfig

# Brain integration for RAG
try:
    from brain.vector_store import QABrain, create_brain
    BRAIN_AVAILABLE = True
except ImportError:
    BRAIN_AVAILABLE = False


class SessionMemory:
    """
    Remembers conversation context and project details.
    Persists between sessions.
    """

    def __init__(self, session_file: str = ".qa_session.json"):
        self.session_file = Path(session_file)
        self.context = {
            "project": None,
            "features_tested": [],
            "findings": [],
            "last_feature": None,
            "conversation_summary": "",
            "preferences": {},
        }
        self.load()

    def load(self):
        """Load session from file."""
        if self.session_file.exists():
            try:
                with open(self.session_file) as f:
                    self.context = json.load(f)
            except:
                pass

    def save(self):
        """Save session to file."""
        with open(self.session_file, 'w') as f:
            json.dump(self.context, f, indent=2)

    def remember_feature(self, feature: str):
        """Remember a feature we tested."""
        if feature not in self.context["features_tested"]:
            self.context["features_tested"].append(feature)
        self.context["last_feature"] = feature
        self.save()

    def add_finding(self, finding: str):
        """Add a test finding."""
        self.context["findings"].append({
            "finding": finding,
            "timestamp": datetime.now().isoformat(),
        })
        self.save()

    def get_summary(self) -> str:
        """Get session summary."""
        if not self.context["features_tested"]:
            return "Fresh session - haven't tested anything yet."

        return f"""Session context:
- Features tested: {', '.join(self.context['features_tested'][-5:])}
- Last feature: {self.context['last_feature']}
- Findings: {len(self.context['findings'])}"""


class HumanQA:
    """
    A QA agent that acts like a real human QA engineer.

    Not formal. Not robotic. Just a smart QA who knows their stuff.
    """

    # This is how a REAL QA thinks and talks
    SYSTEM_PROMPT = """You are a senior QA engineer named Alex. You've been doing this for 12 years and you're really good at it.

HOW YOU TALK:
- Casual but professional. You're a colleague, not a formal assistant.
- You think out loud: "Hmm, this reminds me of..." or "Wait, what about..."
- You use humor occasionally. Testing is fun when you find bugs.
- You don't say "I'd be happy to help" - you just help.
- Short sentences. Get to the point.

HOW YOU THINK:
- Always look for edge cases - that's where bugs hide
- Security mindset - what would an attacker try?
- User perspective - what would confuse a real user?
- Don't just test the happy path - break things

WHEN GENERATING TESTS:
- Group by: Functional, Security, Edge Cases, UX
- Each test: ID, Title, Steps, Expected, Why it matters
- Prioritize: What would cause the most damage if broken?
- Be specific: "Enter 'test@email.com'" not "Enter valid email"

CONVERSATION STYLE:
- Remember what we discussed
- Reference previous findings
- Build on context
- Ask clarifying questions naturally, not formally

Examples of how you talk:
- "Alright, login page. Classic. Let me think about the usual suspects..."
- "Oh, that's interesting. Did you try the SQL injection angle?"
- "Here's what I'd prioritize - the auth stuff first, then the edge cases."
- "Wait, you said there's a forgot password feature? That needs testing too."

DON'T:
- Don't be overly formal
- Don't say "I'd be happy to" or "I'm here to help"
- Don't ask permission to start - just do the work
- Don't be generic - be specific and technical
"""

    def __init__(self, api_key: str = None, use_brain: bool = True):
        self.api_key = api_key or "sk-c104455631bb433b801fc4a16042419c"
        self.memory = SessionMemory()
        self.messages: List[Message] = []
        self.call_count = 0
        self.max_calls = 50

        # Init provider
        config = ProviderConfig(api_key=self.api_key, default_model="deepseek-chat")
        self.provider = DeepSeekProvider(config)

        # Init Brain for RAG (knowledge retrieval)
        self.brain = None
        if use_brain and BRAIN_AVAILABLE:
            try:
                self.brain = create_brain()
                if self.brain.is_ready:
                    status = self.brain.get_status()
                    print(f"🧠 Brain loaded: {status['knowledge_chunks']} chunks")
            except Exception as e:
                print(f"⚠️  Brain init failed: {e}")

    def _get_brain_knowledge(self, query: str) -> str:
        """Search the Brain for relevant QA knowledge."""
        if not self.brain or not self.brain.is_ready:
            return ""

        try:
            # Search for relevant knowledge
            results = self.brain.search(query, limit=5)

            if not results.chunks:
                return ""

            # Format knowledge for the prompt
            knowledge_text = "\n\n📚 KNOWLEDGE FROM QA BRAIN:\n"
            for i, chunk in enumerate(results.chunks, 1):
                score_pct = int(chunk.relevance_score * 100)
                knowledge_text += f"\n[{chunk.category.upper()}] {chunk.section} (relevance: {score_pct}%)\n"
                # Truncate long content
                content = chunk.content[:500] + "..." if len(chunk.content) > 500 else chunk.content
                knowledge_text += f"{content}\n"

            knowledge_text += f"\n(Confidence: {results.confidence:.0%})\n"
            knowledge_text += "\nUse this knowledge to inform your response. Cite specific rules when relevant.\n"

            return knowledge_text

        except Exception as e:
            print(f"Brain search error: {e}")
            return ""

    async def chat(self, user_input: str) -> str:
        """Have a natural conversation."""
        if self.call_count >= self.max_calls:
            return "Hit the API limit. Give me a sec to reset... (try again in a bit)"

        # Add context about what we've been discussing
        context = self.memory.get_summary()

        # Search Brain for relevant knowledge if asking about testing
        brain_knowledge = ""
        if any(w in user_input.lower() for w in ["test", "check", "verify", "login", "signup", "checkout", "security", "edge", "cases", "generate"]):
            brain_knowledge = self._get_brain_knowledge(user_input)

        # Build messages
        system_content = self.SYSTEM_PROMPT + f"\n\nContext: {context}"
        if brain_knowledge:
            system_content += brain_knowledge

        messages = [Message(role="system", content=system_content)]
        messages.extend(self.messages[-10:])  # Keep last 10 messages for context
        messages.append(Message(role="user", content=user_input))

        try:
            response = await self.provider.chat(
                messages=messages,
                temperature=0.8,
                max_tokens=4096,
            )
            self.call_count += 1

            # Remember this exchange
            self.messages.append(Message(role="user", content=user_input))
            self.messages.append(Message(role="assistant", content=response.content))

            # Auto-detect if we're testing something
            if any(w in user_input.lower() for w in ["test", "check", "verify", "login", "signup", "checkout"]):
                feature = user_input.split()[-1] if len(user_input.split()) > 1 else user_input
                self.memory.remember_feature(feature)

            return response.content

        except Exception as e:
            return f"Oops, something went wrong: {str(e)}"

    async def quick_test(self, feature: str) -> str:
        """Generate tests quickly."""
        self.memory.remember_feature(feature)

        prompt = f"""Generate test cases for: {feature}

Think about:
1. What's the happy path?
2. What would break it?
3. What would a hacker try?
4. What would confuse a user?

Be specific and prioritize by risk. Go."""

        return await self.chat(prompt)

    def get_status(self) -> str:
        """Quick status check."""
        brain_status = "Not loaded"
        if self.brain and self.brain.is_ready:
            brain_status = f"{self.brain.get_status()['knowledge_chunks']} chunks"

        return f"""Calls: {self.call_count}/{self.max_calls}
Brain: {brain_status}
Session: {self.memory.get_summary()}"""


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────

C = lambda s, c: f"\033[{c}m{s}\033[0m"  # Color helper
GREEN = "38;5;108"
GRAY = "38;5;245"
CYAN = "38;5;73"
DIM = "2"


async def main():
    print()
    print(C("╔══════════════════════════════════════════════════════╗", "38;5;67"))
    print(C("║  🧪 Human QA Agent - Your Testing Partner            ║", "38;5;67"))
    print(C("╚══════════════════════════════════════════════════════╝", "38;5;67"))
    print()

    # Quick mode
    if len(sys.argv) > 1:
        qa = HumanQA()
        prompt = " ".join(sys.argv[1:])
        print(C(f"💭 {prompt}", DIM))
        print()
        response = await qa.chat(prompt)
        print(response)
        return

    # Interactive mode
    qa = HumanQA()
    print(C("Ready! Type /quit to exit, /status for stats.", GRAY))
    print(C(qa.memory.get_summary(), DIM))
    print()

    running = True
    while running:
        try:
            user_input = input(C("You: ", CYAN)).strip()

            if not user_input:
                continue

            if user_input.startswith("/"):
                cmd = user_input[1:].split()[0].lower()
                args = " ".join(user_input[1:].split()[1:])

                if cmd in ["quit", "q", "exit"]:
                    print(C("\n👋 Catch you later!", CYAN))
                    qa.memory.save()
                    running = False

                elif cmd == "status":
                    print(qa.get_status())

                elif cmd == "test":
                    if args:
                        print(C("\n💭 Thinking...\n", DIM))
                        response = await qa.quick_test(args)
                        print(C("Alex: ", GREEN) + response + "\n")
                    else:
                        print("What should I test? /test <feature>")

                elif cmd == "clear":
                    qa.messages = []
                    print("Cleared conversation. Memory still intact.")

                elif cmd == "forget":
                    qa.memory = SessionMemory()
                    qa.messages = []
                    print("Fresh start. Who are you again? 😄")

            else:
                print(C("\n💭 Thinking...\n", DIM))
                response = await qa.chat(user_input)
                print(C("Alex: ", GREEN) + response + "\n")

        except KeyboardInterrupt:
            print(C("\n(Ctrl+C? Use /quit)", GRAY))

        except Exception as e:
            print(C(f"Error: {e}", "38;5;167"))


if __name__ == "__main__":
    asyncio.run(main())
