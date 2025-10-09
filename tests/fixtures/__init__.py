"""Test fixtures module.

Docker fixtures are handled directly in conftest.py with local replacements.
No external dependencies on flext_tests.fixtures.

Provides generic fixture loading infrastructure for LDAP server quirks testing
following FLEXT architectural patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from .loader import FlextLdifFixtures

# Fixture paths
FIXTURES_DIR: Final[Path] = Path(__file__).parent
OID_FIXTURES_DIR: Final[Path] = FIXTURES_DIR / "oid"


__all__ = [
    # Paths
    "FIXTURES_DIR",
    "OID_FIXTURES_DIR",
    # Main fixture loader class
    "FlextLdifFixtures",
]
