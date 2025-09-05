"""Test Support Utilities for FLEXT-LDIF.

This module provides comprehensive test utilities for real functionality testing
without mocks, bypasses, or fake implementations. Utilities focus on:

- Real LDIF data generation and validation
- Actual service instance creation and configuration
- File-based testing with proper cleanup
- Error scenario generation for comprehensive testing
- Performance testing utilities

All utilities are designed to test real functionality using the actual
flext-ldif libraries and services.
"""

from .ldif_data import LdifTestData
from .real_services import RealServiceFactory
from .test_files import TestFileManager
from .validators import TestValidators

__all__ = [
    "LdifTestData",
    "RealServiceFactory",
    "TestFileManager",
    "TestValidators",
]
