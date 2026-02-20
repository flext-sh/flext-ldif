"""Tests package for flext-ldif.

Unified test infrastructure providing:
- t: TestsFlextLdifTypes (type definitions and TypeVars)
- c: TestsFlextLdifConstants (test constants organized by domain)
- p: TestsFlextLdifProtocols (test protocol definitions)
- m: TestsFlextLdifModels (test model definitions)
- u: TestsFlextLdifUtilities (test utility functions)
- s: FlextLdifTestsServiceBase (base class for test services with factories)
- tm: FlextTestsMatchers (unified matchers for assertions)
- tv: FlextTestsValidator (validation helpers)
- tt: FlextTestsTypes (type helpers for tests)
- tf: FlextTestsFactories (factory helpers)
- tp: TestsFlextLdifProtocols (test protocols alias)

All test files should import these unified infrastructure components:
    from tests import t, c, p, m, u, s, tm, tv, tt, tf, tp

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

# PYTHON_VERSION_GUARD — Do not remove. Managed by scripts/maintenance/enforce_python_version.py
import sys as _sys

if _sys.version_info[:2] != (3, 13):
    _v = (
        f"{_sys.version_info.major}.{_sys.version_info.minor}.{_sys.version_info.micro}"
    )
    raise RuntimeError(
        f"\n{'=' * 72}\n"
        f"FATAL: Python {_v} detected — this project requires Python 3.13.\n"
        f"\n"
        f"The virtual environment was created with the WRONG Python interpreter.\n"
        f"\n"
        f"Fix:\n"
        f"  1. rm -rf .venv\n"
        f"  2. poetry env use python3.13\n"
        f"  3. poetry install\n"
        f"\n"
        f"Or use the workspace Makefile:\n"
        f"  make setup PROJECT=flext-ldif\n"
        f"{'=' * 72}\n"
    )
del _sys
# PYTHON_VERSION_GUARD_END

# Base classes are imported in test_helpers.py
# Only import the enhanced versions here
from tests.base import FlextLdifTestsServiceBase as s
from tests.conftest import FlextLdifFixtures
from tests.constants import (
    Filters,
    OIDs,
    Syntax,
    TestsFlextLdifConstants,
    TestsFlextLdifConstants as c,
)
from tests.models import TestsFlextLdifModels as m
from tests.protocols import TestsFlextLdifProtocols, p, tp
from tests.test_helpers import (
    TestsFlextLdifFixtures as tf,
    TestsFlextLdifMatchers as tm,
    TestsFlextLdifTypes as _TestsFlextLdifTypesHelper,
    TestsFlextLdifValidators as tv,
)
from tests.typings import GenericFieldsDict, TestsFlextLdifTypes as t, tt
from tests.unit.quirks.servers.test_utils import FlextLdifTestUtils
from tests.utilities import (
    RfcTestHelpers,
    TestCategorization,
    TestDeduplicationHelpers,
    TestsFlextLdifUtilities as u,
)

__all__ = [
    "Filters",
    "FlextLdifFixtures",
    "FlextLdifTestUtils",
    "GenericFieldsDict",
    "OIDs",
    "RfcTestHelpers",
    "Syntax",
    "TestCategorization",
    "TestDeduplicationHelpers",
    "TestsFlextLdifConstants",
    "TestsFlextLdifProtocols",
    "_TestsFlextLdifTypesHelper",
    "c",
    "m",
    "p",
    "s",
    "t",
    "tf",
    "tm",
    "tp",
    "tt",
    "tv",
    "u",
]
