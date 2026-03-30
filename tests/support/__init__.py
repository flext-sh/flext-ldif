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
    from tests.support import (
        conftest_factory as conftest_factory,
        ldif_data as ldif_data,
        real_services as real_services,
        test_files as test_files,
        validators as validators,
    )
    from tests.support.conftest_factory import (
        FlextLdifTestConftest as FlextLdifTestConftest,
        tk as tk,
    )
    from tests.support.ldif_data import (
        LdifSample as LdifSample,
        LdifTestData as LdifTestData,
    )
    from tests.support.real_services import (
        FlextLdifTestServiceFactory as FlextLdifTestServiceFactory,
    )
    from tests.support.test_files import FileManager as FileManager
    from tests.support.validators import (
        MockFlextUtilitiesResultHelpers as MockFlextUtilitiesResultHelpers,
        MockMatchers as MockMatchers,
        TestValidators as TestValidators,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FileManager": ["tests.support.test_files", "FileManager"],
    "FlextLdifTestConftest": [
        "tests.support.conftest_factory",
        "FlextLdifTestConftest",
    ],
    "FlextLdifTestServiceFactory": [
        "tests.support.real_services",
        "FlextLdifTestServiceFactory",
    ],
    "LdifSample": ["tests.support.ldif_data", "LdifSample"],
    "LdifTestData": ["tests.support.ldif_data", "LdifTestData"],
    "MockFlextUtilitiesResultHelpers": [
        "tests.support.validators",
        "MockFlextUtilitiesResultHelpers",
    ],
    "MockMatchers": ["tests.support.validators", "MockMatchers"],
    "TestValidators": ["tests.support.validators", "TestValidators"],
    "conftest_factory": ["tests.support.conftest_factory", ""],
    "ldif_data": ["tests.support.ldif_data", ""],
    "real_services": ["tests.support.real_services", ""],
    "test_files": ["tests.support.test_files", ""],
    "tk": ["tests.support.conftest_factory", "tk"],
    "validators": ["tests.support.validators", ""],
}

_EXPORTS: Sequence[str] = [
    "FileManager",
    "FlextLdifTestConftest",
    "FlextLdifTestServiceFactory",
    "LdifSample",
    "LdifTestData",
    "MockFlextUtilitiesResultHelpers",
    "MockMatchers",
    "TestValidators",
    "conftest_factory",
    "ldif_data",
    "real_services",
    "test_files",
    "tk",
    "validators",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
