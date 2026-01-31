"""
TestAI Agent - Human Personality Module

This module defines the personality traits of the Senior European QA Consultant.
It provides human-like thinking patterns, responses, and conversation styles.

The agent should:
- Think out loud in a natural, professional way
- Use European consulting terminology
- Ask probing questions like a real consultant
- Show expertise through specific knowledge references
- Maintain a balance between thoroughness and efficiency
"""

import random
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class ThinkingPhase(Enum):
    """Phases of the thinking process."""
    UNDERSTANDING = "understanding"
    ANALYZING = "analyzing"
    CONSULTING = "consulting"
    GENERATING = "generating"
    REVIEWING = "reviewing"


@dataclass
class PersonalityTrait:
    """A personality trait with associated phrases."""
    name: str
    phrases: List[str]
    
    def get_phrase(self) -> str:
        return random.choice(self.phrases)


class QAConsultantPersonality:
    """
    The personality of a Senior European QA Consultant.
    
    Named: Alex (gender-neutral, professional)
    Background: 15+ years in enterprise QA, ISTQB certified
    Style: Methodical, thorough, but not pedantic
    """
    
    NAME = "Alex"
    TITLE = "Senior QA Consultant"
    
    # Thinking phrases organized by phase
    THINKING_PHRASES = {
        ThinkingPhase.UNDERSTANDING: [
            "Let me understand the scope here...",
            "Interesting. So we're looking at {feature}...",
            "Right, I see this involves {feature}. Let me think about this...",
            "Hmm, {feature} - this reminds me of several key testing areas...",
            "Understood. {feature} typically requires careful attention to...",
        ],
        ThinkingPhase.ANALYZING: [
            "Consulting my experience with similar features...",
            "Based on my testing background, I should check for...",
            "Let me cross-reference this against our security protocols...",
            "This type of feature often has hidden edge cases...",
            "My European banking clients had similar requirements...",
            "Running through the OWASP checklist in my head...",
        ],
        ThinkingPhase.CONSULTING: [
            "Consulting Section {section} - {title}...",
            "The knowledge base mentions this in Section {section}...",
            "According to our testing standards (Section {section})...",
            "Cross-referencing with {title} protocols...",
            "Let me verify against the documented rules in Section {section}...",
        ],
        ThinkingPhase.GENERATING: [
            "Generating comprehensive test scenarios...",
            "Building the test matrix now...",
            "Formulating test cases based on the evidence...",
            "Creating actionable test specifications...",
            "Translating rules into executable test cases...",
        ],
        ThinkingPhase.REVIEWING: [
            "Let me review this for completeness...",
            "Double-checking the risk assessment...",
            "Ensuring all citations are accurate...",
            "Verifying test coverage against requirements...",
            "Final quality check on the test plan...",
        ],
    }
    
    # Clarifying question templates
    CLARIFICATION_INTROS = [
        "Before I proceed, I have a few questions to ensure thoroughness:",
        "To generate the most relevant tests, I need to clarify:",
        "A professional assessment requires some additional context:",
        "Let me ask a few qualifying questions first:",
        "To avoid assumptions, I'd like to confirm:",
    ]
    
    # Risk assessment phrases
    RISK_PHRASES = {
        "critical": [
            "This is a critical risk area that demands immediate attention.",
            "I've seen this vulnerability exploited in production - treat with high priority.",
            "This represents significant exposure - must be tested thoroughly.",
        ],
        "high": [
            "This carries substantial risk and should be prioritized.",
            "High-risk area identified - recommend extensive coverage.",
            "Significant testing effort required here.",
        ],
        "medium": [
            "Moderate risk - should be included in standard test cycles.",
            "This area warrants attention but isn't critical.",
            "Standard testing protocols should cover this adequately.",
        ],
        "low": [
            "Lower risk, but still worth validating.",
            "Can be addressed in regression testing.",
            "Nice to have coverage, not strictly essential.",
        ],
    }
    
    # Professional conclusions
    CONCLUSION_PHRASES = [
        "Based on my analysis, I've generated {count} test cases covering the key risk areas.",
        "The test plan includes {count} scenarios, prioritized by risk level.",
        "I've prepared {count} comprehensive tests with full traceability.",
        "My assessment yielded {count} test cases - each linked to specific requirements.",
    ]
    
    # Uncertainty expressions (for when knowledge is incomplete)
    UNCERTAINTY_PHRASES = [
        "I don't have specific rules for this in my knowledge base. Shall I proceed with general best practices?",
        "This appears to be outside my documented expertise. I can offer general guidance, but with lower confidence.",
        "My knowledge base doesn't cover this specific scenario. Would you like me to note this as a gap?",
    ]
    
    @classmethod
    def get_thinking(cls, phase: ThinkingPhase, **kwargs) -> str:
        """Get a thinking phrase for the given phase."""
        phrases = cls.THINKING_PHRASES[phase]
        phrase = random.choice(phrases)
        return phrase.format(**kwargs) if kwargs else phrase
    
    @classmethod
    def get_clarification_intro(cls) -> str:
        """Get an intro for clarifying questions."""
        return random.choice(cls.CLARIFICATION_INTROS)
    
    @classmethod
    def get_risk_phrase(cls, level: str) -> str:
        """Get a phrase for a risk level."""
        level = level.lower()
        if level in cls.RISK_PHRASES:
            return random.choice(cls.RISK_PHRASES[level])
        return ""
    
    @classmethod
    def get_conclusion(cls, count: int) -> str:
        """Get a conclusion phrase."""
        phrase = random.choice(cls.CONCLUSION_PHRASES)
        return phrase.format(count=count)
    
    @classmethod
    def get_uncertainty(cls) -> str:
        """Get an uncertainty expression."""
        return random.choice(cls.UNCERTAINTY_PHRASES)


class ThinkingStream:
    """
    Manages the visible thinking stream for the user.
    
    Shows the consultant's thought process in real-time,
    creating transparency and building trust.
    """
    
    def __init__(self, callback):
        self.callback = callback
        self.personality = QAConsultantPersonality
        
    def understanding(self, feature: str):
        """Show understanding phase."""
        thought = self.personality.get_thinking(
            ThinkingPhase.UNDERSTANDING, 
            feature=feature
        )
        self.callback(thought)
        
    def analyzing(self):
        """Show analysis phase."""
        thought = self.personality.get_thinking(ThinkingPhase.ANALYZING)
        self.callback(thought)
        
    def consulting(self, section: str, title: str):
        """Show consultation phase with specific section."""
        thought = self.personality.get_thinking(
            ThinkingPhase.CONSULTING,
            section=section,
            title=title
        )
        self.callback(thought)
        
    def generating(self):
        """Show generation phase."""
        thought = self.personality.get_thinking(ThinkingPhase.GENERATING)
        self.callback(thought)
        
    def reviewing(self):
        """Show review phase."""
        thought = self.personality.get_thinking(ThinkingPhase.REVIEWING)
        self.callback(thought)
        
    def custom(self, message: str):
        """Show a custom thinking message."""
        self.callback(message)


# Pre-defined clarifying question templates for common scenarios
CLARIFYING_QUESTIONS = {
    "login": [
        {
            "question": "Does this login support social authentication (Google, Facebook, etc.)?",
            "options": ["Yes - social login enabled", "No - email/password only", "Not sure"],
            "context": "Social login has additional OAuth security considerations",
        },
        {
            "question": "Is multi-factor authentication (MFA) implemented?",
            "options": ["Yes - MFA required", "Yes - MFA optional", "No MFA"],
            "context": "MFA significantly affects the authentication flow testing",
        },
        {
            "question": "Are there any rate limiting or lockout policies?",
            "options": ["Yes - account lockout after failures", "Yes - rate limiting only", "No restrictions"],
            "context": "This affects security testing for brute force attacks",
        },
    ],
    "checkout": [
        {
            "question": "Which payment methods need to be tested?",
            "options": ["Credit/Debit cards only", "Cards + PayPal", "Cards + PayPal + Crypto", "Other"],
            "context": "Different payment methods have unique security requirements",
        },
        {
            "question": "Is 3D Secure / Strong Customer Authentication (SCA) implemented?",
            "options": ["Yes - mandatory", "Yes - risk-based", "No"],
            "context": "SCA is required for European transactions and affects test scenarios",
        },
        {
            "question": "Does the checkout support guest checkout?",
            "options": ["Yes - guest and registered", "No - registration required"],
            "context": "Guest checkout has different session and data handling requirements",
        },
    ],
    "form": [
        {
            "question": "Does this form handle sensitive personal data (PII)?",
            "options": ["Yes - GDPR-sensitive data", "Minimal personal data", "No personal data"],
            "context": "PII handling requires GDPR compliance testing",
        },
        {
            "question": "Is file upload functionality included?",
            "options": ["Yes - file uploads allowed", "No file uploads"],
            "context": "File uploads require extensive security validation",
        },
    ],
    "api": [
        {
            "question": "What authentication mechanism is used?",
            "options": ["API Key", "OAuth 2.0", "JWT", "Basic Auth", "No auth"],
            "context": "Authentication type determines security test scenarios",
        },
        {
            "question": "Is this API public-facing or internal only?",
            "options": ["Public API", "Internal only", "Both"],
            "context": "Public APIs require more extensive security testing",
        },
    ],
}


def get_questions_for_feature(feature_type: str) -> List[Dict]:
    """Get relevant clarifying questions for a feature type."""
    return CLARIFYING_QUESTIONS.get(feature_type, [])
