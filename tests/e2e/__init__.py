# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""End-to-end tests for FLEXT-LDIF complete workflows.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes

    from tests.e2e import test_enterprise

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "test_enterprise": "tests.e2e.test_enterprise",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
