"""Tests package for flext-ldif.

Unified test infrastructure providing:
- t: TestsFlextLdifTypes (type definitions and TypeVars)
- c: TestsFlextLdifConstants (test constants organized by domain)
- p: TestsFlextLdifProtocols (test protocol definitions)
- m: TestsFlextLdifModels (test model definitions)
- u: TestsFlextLdifUtilities (test utility functions)
- s: FlextLdifTestsServiceBase (base class for test services with factories)
- tv: FlextTestsValidator (validation helpers)
- tf: FlextTestsFactories (factory helpers)

All test files should import these unified infrastructure components:
    from tests import t, c, p, m, u, s, tv, tf

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from tests.base import FlextLdifTestsServiceBase as s
from tests.constants import TestsFlextLdifConstants as c
from tests.models import TestsFlextLdifModels as m
from tests.protocols import p
from tests.test_helpers import (
    TestsFlextLdifFixtures as tf,
    TestsFlextLdifValidators as tv,
)
from tests.typings import TestsFlextLdifTypes as t
from tests.utilities import TestsFlextLdifUtilities as u

__all__ = [
    "c",
    "m",
    "p",
    "s",
    "t",
    "tf",
    "tv",
    "u",
]
