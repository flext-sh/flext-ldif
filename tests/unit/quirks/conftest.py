"""Shared fixtures for quirks tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdif

from .servers.conftest import (
    conversion_matrix,
    oid_quirk,
    oid_schema_quirk,
    oud_quirk,
    oud_schema_quirk,
    real_parser_service,
    real_writer_service,
)


@pytest.fixture(autouse=True)
def cleanup_state() -> None:
    """Autouse fixture to clean shared state between tests.

    Runs after each test to prevent state pollution to subsequent tests.
    Ensures test isolation even when fixtures have shared state.
    """
    return
    # Post-test cleanup - ensures each test has clean state


@pytest.fixture
def api() -> FlextLdif:
    """Create FlextLdif API instance for testing."""
    return FlextLdif.get_instance()


__all__ = [
    "api",
    "conversion_matrix",
    "oid_quirk",
    "oid_schema_quirk",
    "oud_quirk",
    "oud_schema_quirk",
    "real_parser_service",
    "real_writer_service",
]
