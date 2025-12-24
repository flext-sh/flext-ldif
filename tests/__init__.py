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

# Base classes are imported in test_helpers.py
# Only import the enhanced versions here
from tests.base import FlextLdifTestsServiceBase as s
from tests.conftest import FlextLdifFixtures
from tests.constants import (
    Filters,
    OIDs,
    RfcTestHelpers,
    Syntax,
    TestCategorization,
    TestDeduplicationHelpers,
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
from tests.typings import TestsFlextLdifTypes as t, tt
from tests.unit.quirks.servers.test_utils import FlextLdifTestUtils
from tests.utilities import TestsFlextLdifUtilities as u

__all__ = [
    "Filters",
    "FlextLdifFixtures",
    "FlextLdifTestUtils",
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
