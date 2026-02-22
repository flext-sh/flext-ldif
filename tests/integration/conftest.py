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

import contextlib
import fcntl
import time
from collections.abc import Callable, Generator
from pathlib import Path

import pytest
from flext_tests import FlextTestsDocker
from ldap3 import ALL, Connection, Server

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

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
LDAP_CONTAINER_NAME = "flext-openldap-test"
LDAP_COMPOSE_FILE = WORKSPACE_ROOT / "docker" / "docker-compose.openldap.yml"
LDAP_SERVICE_NAME = "openldap"
LDAP_PORT = 3390
LDAP_BASE_DN = "dc=flext,dc=local"
LDAP_ADMIN_DN = "cn=admin,dc=flext,dc=local"
LDAP_ADMIN_PASSWORD = "admin123"


def _candidate_bind_credentials() -> tuple[tuple[str, str], ...]:
    return (
        ("cn=admin,dc=flext,dc=local", "admin123"),
        ("cn=admin,dc=flext,dc=local", "REDACTED_LDAP_BIND_PASSWORD123"),
        (
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            "REDACTED_LDAP_BIND_PASSWORD123",
        ),
    )


@contextlib.contextmanager
def _lock_file(worker_id: str) -> Generator[None]:
    _ = worker_id
    lock_path = Path.home() / ".flext" / f"{LDAP_CONTAINER_NAME}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _wait_for_ldap_ready(
    server_url: str,
    max_wait: float = 10.0,
) -> tuple[str, str] | None:
    waited = 0.0
    interval = 1.0
    while waited < max_wait:
        with contextlib.suppress(Exception):
            server = Server(server_url, get_info=ALL)
            for bind_dn, password in _candidate_bind_credentials():
                conn = Connection(
                    server,
                    user=bind_dn,
                    password=password,
                    auto_bind=False,
                )
                if conn.bind():
                    conn.unbind()
                    return (bind_dn, password)
                conn.unbind()
        time.sleep(interval)
        waited += interval
    return None


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
def ldap_container(worker_id: str) -> dict[str, object]:
    """Ensure shared OpenLDAP container is available for integration tests."""
    docker_control = FlextTestsDocker(
        workspace_root=WORKSPACE_ROOT, worker_id=worker_id
    )
    server_url = f"ldap://localhost:{LDAP_PORT}"

    with _lock_file(worker_id):
        start_result = docker_control.start_existing_container(LDAP_CONTAINER_NAME)
        if start_result.is_failure:
            compose_result = docker_control.compose_up(
                str(LDAP_COMPOSE_FILE),
                LDAP_SERVICE_NAME,
            )
            if compose_result.is_failure:
                pytest.skip(
                    f"Could not start shared OpenLDAP container: {compose_result.error}"
                )

        port_result = docker_control.wait_for_port_ready("localhost", LDAP_PORT, 15)
        if port_result.is_failure or not port_result.value:
            pytest.skip(f"LDAP container port {LDAP_PORT} is not ready")

        bind_credentials = _wait_for_ldap_ready(server_url)
        if bind_credentials is None:
            pytest.skip("LDAP container is running but bind is not ready")

    bind_dn, bind_password = bind_credentials

    return {
        "server_url": server_url,
        "host": "localhost",
        "bind_dn": bind_dn,
        "password": bind_password,
        "base_dn": LDAP_BASE_DN,
        "port": LDAP_PORT,
        "use_ssl": False,
        "worker_id": worker_id,
    }


@pytest.fixture(scope="session")
def ldap_container_shared(ldap_container: dict[str, object]) -> str:
    """Provide LDAP connection URL for tests requiring Docker container."""
    default_url = f"ldap://localhost:{LDAP_PORT}"
    return str(ldap_container.get("server_url", default_url))


@pytest.fixture
def unique_dn_suffix(worker_id: str, request: pytest.FixtureRequest) -> str:
    """Build a unique suffix for LDAP DNs per test execution."""
    test_name = request.node.name if hasattr(request, "node") else "unknown"
    test_name_clean = "".join(
        ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in test_name
    )[:20]
    return f"{worker_id}-{int(time.time() * 1000)}-{test_name_clean}"


@pytest.fixture
def make_test_username(unique_dn_suffix: str) -> Callable[[str], str]:
    """Return a factory that creates unique usernames."""

    def _make(username: str) -> str:
        return f"{username}-{unique_dn_suffix}"

    return _make


@pytest.fixture
def make_test_base_dn(unique_dn_suffix: str) -> Callable[[str], str]:
    """Return a factory that creates unique test base DNs."""
    base_dn = "dc=flext,dc=local"

    def _make(ou: str) -> str:
        return f"ou={ou}-{unique_dn_suffix},{base_dn}"

    return _make


@pytest.fixture
def ldap_connection(ldap_container: dict[str, object]) -> Generator[Connection]:
    """Provide a bound LDAP connection or skip when unavailable."""
    server_url = str(ldap_container.get("server_url", f"ldap://localhost:{LDAP_PORT}"))
    bind_dn = str(ldap_container.get("bind_dn", LDAP_ADMIN_DN))
    password = str(ldap_container.get("password", LDAP_ADMIN_PASSWORD))

    server = Server(server_url, get_info=ALL)
    conn = Connection(
        server,
        user=bind_dn,
        password=password,
        auto_bind=False,
    )
    try:
        if not conn.bind():
            pytest.skip(
                f"LDAP server not available at {server_url} for bind_dn={bind_dn}",
            )
    except Exception as exc:
        pytest.skip(f"LDAP server not available: {exc}")

    yield conn
    conn.unbind()


@pytest.fixture
def clean_test_ou(
    ldap_connection: Connection,
    make_test_base_dn: Callable[[str], str],
) -> Generator[str]:
    """Create and clean up an isolated OU for integration tests."""
    test_ou_dn = make_test_base_dn("FlextLdifTests")
    with contextlib.suppress(Exception):
        ldap_connection.search(test_ou_dn, "(objectClass=*)", search_scope="SUBTREE")
        if ldap_connection.entries:
            dns_to_delete = [entry.entry_dn for entry in ldap_connection.entries]
            for dn in reversed(dns_to_delete):
                with contextlib.suppress(Exception):
                    ldap_connection.delete(dn)

    with contextlib.suppress(Exception):
        ldap_connection.add(
            test_ou_dn, ["organizationalUnit"], {"ou": "FlextLdifTests"}
        )

    yield test_ou_dn

    with contextlib.suppress(Exception):
        ldap_connection.search(test_ou_dn, "(objectClass=*)", search_scope="SUBTREE")
        if ldap_connection.entries:
            dns_to_delete = [entry.entry_dn for entry in ldap_connection.entries]
            for dn in reversed(dns_to_delete):
                with contextlib.suppress(Exception):
                    ldap_connection.delete(dn)
