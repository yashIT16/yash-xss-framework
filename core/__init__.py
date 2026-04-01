"""Core XSS scanner engine."""
from .scanner_engine import (
    YASHScanner, WAFDetector, ReflectionTester, PolymorphicEngine,
    ReflectionContext, WAFType, WAFResult, ReflectionResult
)

__all__ = [
    'YASHScanner', 'WAFDetector', 'ReflectionTester', 'PolymorphicEngine',
    'ReflectionContext', 'WAFType', 'WAFResult', 'ReflectionResult'
]
