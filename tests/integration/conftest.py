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

import socket
from pathlib import Path

import pytest

from flext_ldif import (
    FlextLdif,
    FlextLdifParser,
    FlextLdifProtocols,
    FlextLdifWriter,
    p,
)
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.conversion import FlextLdifConversion
from flext_ldif.services.server import FlextLdifServer
from tests.conftest import FlextLdifFixtures

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
) -> list[p.Entry]:
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
    return result.value


@pytest.fixture
def oid_entries(
    api: FlextLdif,
    oid_entries_fixture: str,
) -> list[p.Entry]:
    """Parse OID entries fixture into Entry models.

    Args:
        api: FlextLdif API instance.
        oid_entries_fixture: OID entries fixture data.

    Returns:
        list[p.Entry]: Parsed entries.

    Raises:
        AssertionError: If parsing fails.

    """
    result = api.parse(oid_entries_fixture)
    assert result.is_success, f"OID entries parsing failed: {result.error}"
    return result.value


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
) -> list[p.Entry]:
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
    return result.value


@pytest.fixture
def oud_entries(
    api: FlextLdif,
    oud_entries_fixture: str,
) -> list[p.Entry]:
    """Parse OUD entries fixture into Entry models.

    Args:
        api: FlextLdif API instance.
        oud_entries_fixture: OUD entries fixture data.

    Returns:
        list[p.Entry]: Parsed entries.

    Raises:
        AssertionError: If parsing fails.

    """
    result = api.parse(oud_entries_fixture)
    assert result.is_success, f"OUD entries parsing failed: {result.error}"
    return result.value


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
) -> list[p.Entry]:
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
    return result.value


@pytest.fixture
def openldap_entries(
    api: FlextLdif,
    openldap_entries_fixture: str,
) -> list[p.Entry]:
    """Parse OpenLDAP entries fixture into Entry models.

    Args:
        api: FlextLdif API instance.
        openldap_entries_fixture: OpenLDAP entries fixture data.

    Returns:
        list[p.Entry]: Parsed entries.

    Raises:
        AssertionError: If parsing fails.

    """
    result = api.parse(openldap_entries_fixture)
    assert result.is_success, f"OpenLDAP entries parsing failed: {result.error}"
    return result.value


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
) -> list[p.Entry]:
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
    return result.value


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


# ============================================================================
# CONVERSION TEST FIXTURES
# ============================================================================


@pytest.fixture
def conversion_matrix() -> FlextLdifConversion:
    """Create FlextLdifConversion instance for conversion tests."""
    return FlextLdifConversion()


@pytest.fixture
def server() -> FlextLdifServer:
    """Get FlextLdifServer instance for quirk management."""
    return FlextLdifServer()


@pytest.fixture
def oid_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OID server quirk via FlextLdifServer API."""
    quirk_result = server.quirk("oid")
    assert quirk_result.is_success, (
        f"OID quirk must be registered: {quirk_result.error}"
    )
    return quirk_result.value


@pytest.fixture
def oud_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OUD server quirk via FlextLdifServer API."""
    quirk_result = server.get_base_quirk("oud")
    assert quirk_result.is_success, (
        f"OUD quirk must be registered: {quirk_result.error}"
    )
    return quirk_result.value


@pytest.fixture
def oid_schema_quirk(
    oid_quirk: FlextLdifServersBase,
) -> FlextLdifProtocols.Quirks.SchemaProtocol:
    """Create OID schema quirk instance for conversion tests."""
    return oid_quirk.schema_quirk


@pytest.fixture
def oud_schema_quirk(
    oud_quirk: FlextLdifServersBase,
) -> FlextLdifProtocols.Quirks.SchemaProtocol:
    """Create OUD schema quirk instance for conversion tests."""
    return oud_quirk.schema_quirk


@pytest.fixture
def oid_acl_quirk(
    oid_quirk: FlextLdifServersBase,
) -> FlextLdifProtocols.Quirks.AclProtocol:
    """Create OID ACL quirk instance for conversion tests."""
    return oid_quirk.acl_quirk


@pytest.fixture
def oud_acl_quirk(
    oud_quirk: FlextLdifServersBase,
) -> FlextLdifProtocols.Quirks.AclProtocol:
    """Create OUD ACL quirk instance for conversion tests."""
    return oud_quirk.acl_quirk


# ============================================================================
# LDAP CONTAINER FIXTURES
# ============================================================================


@pytest.fixture(scope="session")
def ldap_container_shared() -> str:
    """Provide LDAP connection URL for tests requiring Docker container.

    This fixture provides the LDAP connection URL for integration tests that
    need to interact with a real LDAP server. It skips tests if the container
    is not running.

    Returns:
        str: LDAP connection URL (e.g., "ldap://localhost:3390")

    """
    port = 3390  # Default LDAP port from docker-compose.openldap.yml

    # Check if port is available (container is running)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(("localhost", port))
        sock.close()
        if result != 0:
            pytest.skip(
                f"LDAP container not running on port {port}. "
                f"Start with: cd /home/marlonsc/flext/docker && "
                f"docker compose -f docker-compose.openldap.yml up -d",
            )
    except OSError:
        pytest.skip(f"Could not check LDAP container on port {port}")

    return f"ldap://localhost:{port}"
