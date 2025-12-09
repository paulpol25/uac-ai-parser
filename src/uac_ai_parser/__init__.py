# UAC AI Parser - Source Package
"""
UAC AI Parser - AI-powered forensic analysis for UAC outputs.

This package provides intelligent parsing and analysis of Unix-like
Artifacts Collector (UAC) outputs using LLM technology for enhanced
incident response and digital forensics.
"""

from uac_ai_parser.core.parser import UACParser
from uac_ai_parser.ai.analyzer import AIAnalyzer
from uac_ai_parser.models.artifacts import UACOutput, Bodyfile, TimelineEvent

__version__ = "0.1.0"
__all__ = [
    "UACParser",
    "AIAnalyzer", 
    "UACOutput",
    "Bodyfile",
    "TimelineEvent",
]
