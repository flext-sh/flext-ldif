"""Shared fixtures for quirks tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdif

from .servers.conftest import (
    ConversionTestConstants,
    conversion_constants,
    conversion_matrix,
    oid_quirk,
    oid_schema_quirk,
    oud_quirk,
    oud_schema_quirk,
    real_parser_service,
    real_writer_service,
)


@pytest.fixture
def api() -> FlextLdif:
    """Create FlextLdif API instance for testing."""
    return FlextLdif.get_instance()


__all__ = [
    "ConversionTestConstants",
    "api",
    "conversion_constants",
    "conversion_matrix",
    "oid_quirk",
    "oid_schema_quirk",
    "oud_quirk",
    "oud_schema_quirk",
    "real_parser_service",
    "real_writer_service",
]
