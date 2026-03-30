# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Test support utilities for FLEXT-LDIF testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.support.conftest_factory import *
    from tests.support.ldif_data import *
    from tests.support.real_services import *
    from tests.support.test_files import *
    from tests.support.validators import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "FileManager": "tests.support.test_files",
    "FlextLdifTestConftest": "tests.support.conftest_factory",
    "FlextLdifTestServiceFactory": "tests.support.real_services",
    "LdifSample": "tests.support.ldif_data",
    "LdifTestData": "tests.support.ldif_data",
    "MockFlextUtilitiesResultHelpers": "tests.support.validators",
    "MockMatchers": "tests.support.validators",
    "TestValidators": "tests.support.validators",
    "conftest_factory": "tests.support.conftest_factory",
    "ldif_data": "tests.support.ldif_data",
    "real_services": "tests.support.real_services",
    "test_files": "tests.support.test_files",
    "tk": "tests.support.conftest_factory",
    "validators": "tests.support.validators",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
