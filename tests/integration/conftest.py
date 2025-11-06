"""Centralized pytest fixtures for integration tests.

This module provides all fixtures needed for integration tests across flext-ldif:
- FlextLdif API instances
- Fixture data from all supported servers (OID, OUD, OpenLDAP, RFC)
- Parsed entries for different fixture types (schema, acl, entries, integration)
- Common test utilities and helpers

Fixtures are organized by server type and can be used in any integration test.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from flext_ldif import FlextLdif
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.writer import FlextLdifWriter

from ..fixtures.loader import FlextLdifFixtures

if TYPE_CHECKING:
    from flext_ldif.typings import FlextLdifEntry


# ============================================================================
# API FIXTURES
# ============================================================================


@pytest.fixture
def api() -> FlextLdif:
    """Create FlextLdif API instance for testing.

    Returns:
        FlextLdif: Configured API instance ready for parsing and writing.

    """
    return FlextLdif.get_instance()


@pytest.fixture
def parser() -> FlextLdifParser:
    """Create FlextLdif parser service for testing.

    Returns:
        FlextLdifParser: Configured parser service.

    """
    return FlextLdifParser()


@pytest.fixture
def writer() -> FlextLdifWriter:
    """Create FlextLdif writer service for testing.

    Returns:
        FlextLdifWriter: Configured writer service.

    """
    return FlextLdifWriter()


# ============================================================================
# OID SERVER FIXTURES
# ============================================================================


@pytest.fixture
def oid_schema_fixture() -> str:
    """Load OID schema fixture data.

    Returns:
        str: Complete OID schema fixture in LDIF format.

    """
    loader = FlextLdifFixtures.OID()
    return loader.schema()


@pytest.fixture
def oid_acl_fixture() -> str:
    """Load OID ACL fixture data.

    Returns:
        str: Complete OID ACL fixture in LDIF format.

    """
    loader = FlextLdifFixtures.OID()
    return loader.acl()


@pytest.fixture
def oid_entries_fixture() -> str:
    """Load OID entries fixture data.

    Returns:
        str: Complete OID entries fixture in LDIF format.

    """
    loader = FlextLdifFixtures.OID()
    return loader.entries()


@pytest.fixture
def oid_integration_fixture() -> str:
    """Load OID integration fixture data.

    Returns:
        str: Complete OID integration fixture in LDIF format.

    """
    loader = FlextLdifFixtures.OID()
    return loader.integration()


@pytest.fixture
def oid_schema_entries(
    api: FlextLdif,
    oid_schema_fixture: str,
) -> list[FlextLdifEntry]:
    """Parse OID schema fixture into Entry models.

    Args:
        api: FlextLdif API instance.
        oid_schema_fixture: OID schema fixture data.

    Returns:
        list[FlextLdifEntry]: Parsed schema entries.

    Raises:
        AssertionError: If parsing fails.

    """
    result = api.parse(oid_schema_fixture)
    assert result.is_success, f"OID schema parsing failed: {result.error}"
    return result.unwrap()


@pytest.fixture
def oid_entries(
    api: FlextLdif,
    oid_entries_fixture: str,
) -> list[FlextLdifEntry]:
    """Parse OID entries fixture into Entry models.

    Args:
        api: FlextLdif API instance.
        oid_entries_fixture: OID entries fixture data.

    Returns:
        list[FlextLdifEntry]: Parsed entries.

    Raises:
        AssertionError: If parsing fails.

    """
    result = api.parse(oid_entries_fixture)
    assert result.is_success, f"OID entries parsing failed: {result.error}"
    return result.unwrap()


# ============================================================================
# OUD SERVER FIXTURES
# ============================================================================


@pytest.fixture
def oud_schema_fixture() -> str:
    """Load OUD schema fixture data.

    Returns:
        str: Complete OUD schema fixture in LDIF format.

    """
    loader = FlextLdifFixtures.OUD()
    return loader.schema()


@pytest.fixture
def oud_acl_fixture() -> str:
    """Load OUD ACL fixture data.

    Returns:
        str: Complete OUD ACL fixture in LDIF format.

    """
    loader = FlextLdifFixtures.OUD()
    return loader.acl()


@pytest.fixture
def oud_entries_fixture() -> str:
    """Load OUD entries fixture data.

    Returns:
        str: Complete OUD entries fixture in LDIF format.

    """
    loader = FlextLdifFixtures.OUD()
    return loader.entries()


@pytest.fixture
def oud_integration_fixture() -> str:
    """Load OUD integration fixture data.

    Returns:
        str: Complete OUD integration fixture in LDIF format.

    """
    loader = FlextLdifFixtures.OUD()
    return loader.integration()


@pytest.fixture
def oud_schema_entries(
    api: FlextLdif,
    oud_schema_fixture: str,
) -> list[FlextLdifEntry]:
    """Parse OUD schema fixture into Entry models.

    Args:
        api: FlextLdif API instance.
        oud_schema_fixture: OUD schema fixture data.

    Returns:
        list[FlextLdifEntry]: Parsed schema entries.

    Raises:
        AssertionError: If parsing fails.

    """
    result = api.parse(oud_schema_fixture)
    assert result.is_success, f"OUD schema parsing failed: {result.error}"
    return result.unwrap()


@pytest.fixture
def oud_entries(
    api: FlextLdif,
    oud_entries_fixture: str,
) -> list[FlextLdifEntry]:
    """Parse OUD entries fixture into Entry models.

    Args:
        api: FlextLdif API instance.
        oud_entries_fixture: OUD entries fixture data.

    Returns:
        list[FlextLdifEntry]: Parsed entries.

    Raises:
        AssertionError: If parsing fails.

    """
    result = api.parse(oud_entries_fixture)
    assert result.is_success, f"OUD entries parsing failed: {result.error}"
    return result.unwrap()


# ============================================================================
# OPENLDAP SERVER FIXTURES
# ============================================================================


@pytest.fixture
def openldap_schema_fixture() -> str:
    """Load OpenLDAP schema fixture data.

    Returns:
        str: Complete OpenLDAP schema fixture in LDIF format.

    """
    loader = FlextLdifFixtures.OpenLDAP()
    return loader.schema()


@pytest.fixture
def openldap_acl_fixture() -> str:
    """Load OpenLDAP ACL fixture data.

    Returns:
        str: Complete OpenLDAP ACL fixture in LDIF format.

    """
    loader = FlextLdifFixtures.OpenLDAP()
    return loader.acl()


@pytest.fixture
def openldap_entries_fixture() -> str:
    """Load OpenLDAP entries fixture data.

    Returns:
        str: Complete OpenLDAP entries fixture in LDIF format.

    """
    loader = FlextLdifFixtures.OpenLDAP()
    return loader.entries()


@pytest.fixture
def openldap_integration_fixture() -> str:
    """Load OpenLDAP integration fixture data.

    Returns:
        str: Complete OpenLDAP integration fixture in LDIF format.

    """
    loader = FlextLdifFixtures.OpenLDAP()
    return loader.integration()


@pytest.fixture
def openldap_schema_entries(
    api: FlextLdif,
    openldap_schema_fixture: str,
) -> list[FlextLdifEntry]:
    """Parse OpenLDAP schema fixture into Entry models.

    Args:
        api: FlextLdif API instance.
        openldap_schema_fixture: OpenLDAP schema fixture data.

    Returns:
        list[FlextLdifEntry]: Parsed schema entries.

    Raises:
        AssertionError: If parsing fails.

    """
    result = api.parse(openldap_schema_fixture)
    assert result.is_success, f"OpenLDAP schema parsing failed: {result.error}"
    return result.unwrap()


@pytest.fixture
def openldap_entries(
    api: FlextLdif,
    openldap_entries_fixture: str,
) -> list[FlextLdifEntry]:
    """Parse OpenLDAP entries fixture into Entry models.

    Args:
        api: FlextLdif API instance.
        openldap_entries_fixture: OpenLDAP entries fixture data.

    Returns:
        list[FlextLdifEntry]: Parsed entries.

    Raises:
        AssertionError: If parsing fails.

    """
    result = api.parse(openldap_entries_fixture)
    assert result.is_success, f"OpenLDAP entries parsing failed: {result.error}"
    return result.unwrap()


# ============================================================================
# RFC REFERENCE FIXTURES
# ============================================================================


@pytest.fixture
def rfc_schema_fixture() -> str:
    """Load RFC reference schema fixture data.

    Returns:
        str: Complete RFC schema fixture in LDIF format.

    """
    loader = FlextLdifFixtures.RFC()
    return loader.schema()


@pytest.fixture
def rfc_schema_entries(
    api: FlextLdif,
    rfc_schema_fixture: str,
) -> list[FlextLdifEntry]:
    """Parse RFC schema fixture into Entry models.

    Args:
        api: FlextLdif API instance.
        rfc_schema_fixture: RFC schema fixture data.

    Returns:
        list[FlextLdifEntry]: Parsed schema entries.

    Raises:
        AssertionError: If parsing fails.

    """
    result = api.parse(rfc_schema_fixture)
    assert result.is_success, f"RFC schema parsing failed: {result.error}"
    return result.unwrap()


# ============================================================================
# PARAMETRIZED FIXTURE PROVIDERS
# ============================================================================


@pytest.fixture
def all_schema_fixtures() -> dict[str, str]:
    """Provide all schema fixtures by server type.

    Returns:
        dict[str, str]: Dictionary mapping server type to schema fixture.

    """
    return {
        "oid": FlextLdifFixtures.OID().schema(),
        "oud": FlextLdifFixtures.OUD().schema(),
        "openldap": FlextLdifFixtures.OpenLDAP().schema(),
        "rfc": FlextLdifFixtures.RFC().schema(),
    }


@pytest.fixture
def all_entries_fixtures() -> dict[str, str]:
    """Provide all entries fixtures by server type.

    Returns:
        dict[str, str]: Dictionary mapping server type to entries fixture.

    """
    return {
        "oid": FlextLdifFixtures.OID().entries(),
        "oud": FlextLdifFixtures.OUD().entries(),
        "openldap": FlextLdifFixtures.OpenLDAP().entries(),
    }


@pytest.fixture
def all_acl_fixtures() -> dict[str, str]:
    """Provide all ACL fixtures by server type.

    Returns:
        dict[str, str]: Dictionary mapping server type to ACL fixture.

    """
    return {
        "oid": FlextLdifFixtures.OID().acl(),
        "oud": FlextLdifFixtures.OUD().acl(),
        "openldap": FlextLdifFixtures.OpenLDAP().acl(),
    }


@pytest.fixture
def all_integration_fixtures() -> dict[str, str]:
    """Provide all integration fixtures by server type.

    Returns:
        dict[str, str]: Dictionary mapping server type to integration fixture.

    """
    return {
        "oid": FlextLdifFixtures.OID().integration(),
        "oud": FlextLdifFixtures.OUD().integration(),
        "openldap": FlextLdifFixtures.OpenLDAP().integration(),
    }


# ============================================================================
# TEMPORARY FIXTURES
# ============================================================================


@pytest.fixture
def tmp_ldif_path(tmp_path: Path) -> Path:
    """Create temporary LDIF file path.

    Args:
        tmp_path: pytest temporary directory.

    Returns:
        Path: Path to temporary LDIF file.

    """
    return tmp_path / "test_output.ldif"


@pytest.fixture
def fixtures_dir() -> Path:
    """Get path to fixtures directory.

    Returns:
        Path: Absolute path to tests/fixtures directory.

    """
    return Path(__file__).parent.parent / "fixtures"


# ============================================================================
# CLEANUP FIXTURES
# ============================================================================


@pytest.fixture(autouse=True)
def _reset_api_singleton() -> None:
    """Reset FlextLdif singleton after each test.

    This ensures tests don't interfere with each other via shared state.
    """
    return
    # FlextLdif.reset_instance() if needed (check if API has this method)
