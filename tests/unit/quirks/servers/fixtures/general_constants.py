"""General test constants for backward compatibility.

This module provides an alias to TestsFlextLdifConstants.General for backward
compatibility with existing test files that import TestGeneralConstants.

All constants are now consolidated in tests/constants.py under TestsFlextLdifConstants.General.
This module provides a simple alias to maintain backward compatibility.
"""

from __future__ import annotations

from tests.constants import TestsFlextLdifConstants

# Alias for backward compatibility
TestGeneralConstants = TestsFlextLdifConstants.General

__all__ = ["TestGeneralConstants"]
