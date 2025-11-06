"""Shared fixtures for server quirks tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from flext_ldif.api import FlextLdif


@pytest.fixture(scope="module")
def ldif_api() -> FlextLdif:
    """Provides a FlextLdif API instance for the test module.

    Creates a FlextLdif instance using the singleton pattern.
    """
    from flext_ldif.api import FlextLdif

    # Use singleton to avoid initialization issues
    return FlextLdif.get_instance()
