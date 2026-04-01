# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Test support utilities for FLEXT-LDIF testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes

    from tests.support import (
        conftest_factory,
        ldif_data,
        real_services,
        test_files,
        validators,
    )
    from tests.support.conftest_factory import FlextLdifTestConftest, tk
    from tests.support.ldif_data import LdifSample, LdifTestData
    from tests.support.real_services import FlextLdifTestServiceFactory
    from tests.support.test_files import FileManager
    from tests.support.validators import (
        MockFlextUtilitiesResultHelpers,
        MockMatchers,
        TestValidators,
    )

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
