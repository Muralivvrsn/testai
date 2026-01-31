"""
TestAI Agent - Test Scenario Module

AI-powered test scenario generation with realistic data,
user journey simulation, and edge case discovery.
"""

from .generator import (
    ScenarioGenerator,
    TestScenario,
    ScenarioType,
    UserPersona,
    create_scenario_generator,
)

from .data_factory import (
    DataFactory,
    DataProfile,
    LocaleData,
    create_data_factory,
)

from .journey import (
    JourneySimulator,
    UserJourney,
    JourneyStep,
    JourneyOutcome,
    create_journey_simulator,
)

__all__ = [
    # Generator
    "ScenarioGenerator",
    "TestScenario",
    "ScenarioType",
    "UserPersona",
    "create_scenario_generator",
    # Data Factory
    "DataFactory",
    "DataProfile",
    "LocaleData",
    "create_data_factory",
    # Journey
    "JourneySimulator",
    "UserJourney",
    "JourneyStep",
    "JourneyOutcome",
    "create_journey_simulator",
]
