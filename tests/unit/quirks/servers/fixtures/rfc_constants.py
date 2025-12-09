"""RFC test constants for backward compatibility.

This module provides an alias to TestsFlextLdifConstants.Rfc for backward
compatibility with existing test files that import TestsRfcConstants.

All constants are now consolidated in tests/constants.py under TestsFlextLdifConstants.Rfc.
This module provides a simple alias to maintain backward compatibility.
"""

from __future__ import annotations

from tests.constants import TestsFlextLdifConstants

# Alias for backward compatibility
TestsRfcConstants = TestsFlextLdifConstants.Rfc

__all__ = ["TestsRfcConstants"]
