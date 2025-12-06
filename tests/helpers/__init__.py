"""LDIF test helpers package - DEPRECATED.

DEPRECATED: Use unified test infrastructure from tests/ root instead.

All test helpers have been consolidated into:
- tests/base.py - FlextLdifTestsServiceBase (unified base class)
- tests/__init__.py - unified imports (t, c, p, m, u, s, tm, tv, tt, tf)
- tests/test_helpers.py - enhanced test helpers (tv, tt, tf, tm)
- tests/conftest.py - pytest fixtures

Old helpers have been renamed to .bak:
- constants.py.bak
- models.py.bak
- protocols.py.bak
- typings.py.bak
- utilities.py.bak

Use these imports instead:
    from tests import t, c, p, m, u, s, tm, tv, tt, tf
    from tests.base import s
    from tests.test_helpers import tm, tv, tt, tf

Temporary compatibility layer provided in compat.py for migration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Temporary compatibility layer for deprecated helpers
from .compat import (
    FixtureTestHelpers,
    FlextLdifTestFactories,
    OptimizedLdifTestHelpers,
    TestAssertions,
    TestDeduplicationHelpers,
)

__all__ = [
    "FixtureTestHelpers",
    "FlextLdifTestFactories",
    "OptimizedLdifTestHelpers",
    "TestAssertions",
    "TestDeduplicationHelpers",
]
