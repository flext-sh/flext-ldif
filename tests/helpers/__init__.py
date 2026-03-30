# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
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

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.helpers import example_refactoring

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "example_refactoring": "tests.helpers.example_refactoring",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
