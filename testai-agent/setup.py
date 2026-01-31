"""
TestAI Agent - Package Setup

Install with:
    pip install -e .
    
Or:
    python setup.py install
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "testai_agent" / "README.md"
long_description = ""
if readme_path.exists():
    long_description = readme_path.read_text()

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = [
        line.strip() 
        for line in requirements_path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="testai-agent",
    version="1.0.0",
    author="TestAI Team",
    author_email="alex@testai.agent",
    description="Cognitive QA System - Senior European QA Consultant",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/testai/testai-agent",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.0.0",
        ],
        "web": [
            "fastapi>=0.100.0",
            "uvicorn>=0.23.0",
        ],
        "execution": [
            "playwright>=1.40.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "testai=testai_agent.main:main",
            "testai-demo=demo:main",
        ],
    },
    package_data={
        "testai_agent": [
            "*.md",
            "*.txt",
        ],
    },
    include_package_data=True,
)
