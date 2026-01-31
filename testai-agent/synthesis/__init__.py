"""
TestAI Agent - Test Synthesis Module

Intelligent test synthesis that combines multiple sources,
patterns, and domain knowledge to generate comprehensive tests.
"""

from .combiner import (
    TestCombiner,
    CombinationStrategy,
    CombinedTest,
    create_test_combiner,
)

from .enricher import (
    TestEnricher,
    EnrichmentSource,
    EnrichedTest,
    create_test_enricher,
)

from .synthesizer import (
    TestSynthesizer,
    SynthesisConfig,
    SynthesizedSuite,
    create_test_synthesizer,
)

__all__ = [
    # Combiner
    "TestCombiner",
    "CombinationStrategy",
    "CombinedTest",
    "create_test_combiner",
    # Enricher
    "TestEnricher",
    "EnrichmentSource",
    "EnrichedTest",
    "create_test_enricher",
    # Synthesizer
    "TestSynthesizer",
    "SynthesisConfig",
    "SynthesizedSuite",
    "create_test_synthesizer",
]
