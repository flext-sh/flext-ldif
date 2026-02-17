"""Shared fixtures for quirks tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdif
from tests.conftest import FlextLdifFixtures
from tests.unit.quirks.servers.conftest import (
    conversion_matrix,
    oid_quirk,
    oid_schema_quirk,
    oud_quirk,
    oud_schema_quirk,
    real_parser_service,
    real_writer_service,
)
from tests.unit.servers.test_conversion_matrix import ConversionTestConstants


@pytest.fixture
def api() -> FlextLdif:
    """Create FlextLdif API instance for testing."""
    return FlextLdif.get_instance()


@pytest.fixture
def oid_fixtures() -> FlextLdifFixtures.OID:
    """Provide OID fixture loader for tests."""
    return FlextLdifFixtures.get_oid()


@pytest.fixture
def oud_fixtures() -> FlextLdifFixtures.OUD:
    """Provide OUD fixture loader for tests."""
    return FlextLdifFixtures.get_oud()


@pytest.fixture
def conversion_constants() -> ConversionTestConstants:
    """Provide ConversionTestConstants for tests."""
    return ConversionTestConstants()


__all__ = [
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
