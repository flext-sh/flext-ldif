"""Centralized pytest fixtures for integration tests.

This module provides all fixtures needed for integration tests across flext-ldif:
- ldif API instances
- Fixture data from all supported servers (OID, OUD, OpenLDAP, RFC)
- Parsed entries for different fixture types (schema, acl, entries, integration)
- Common test utilities and helpers

Fixtures are organized by server type and can be used in any integration test.
Uses centralized Docker/LDAP infrastructure from c.Ldif.Docker and u.Ldif.Tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable, Generator, Mapping, Sequence
from pathlib import Path

import pytest
from flext_ldap import FlextLdapUtilities as ldap_u

from flext_ldif import (
    FlextLdifConversion,
    FlextLdifParser,
    FlextLdifServer,
    FlextLdifServersBase,
    FlextLdifServersBaseSchema,
    FlextLdifServersBaseSchemaAcl,
    FlextLdifWriter,
    ldif,
)
from tests import FlextLdifFixtures, c, m, p, t, u

# Centralized Docker constants — single source of truth
_D = c.Ldif.Docker
WORKSPACE_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def api() -> ldif:
    """Create ldif API instance for testing."""
    return ldif.get_instance()


@pytest.fixture
def parser() -> FlextLdifParser:
    """Create ldif parser service for testing."""
    return FlextLdifParser()


@pytest.fixture
def writer() -> FlextLdifWriter:
    """Create ldif writer service for testing."""
    return FlextLdifWriter()


@pytest.fixture
def oid_schema_fixture() -> str:
    """Load OID schema fixture data."""
    loader = FlextLdifFixtures.OID()
    return loader.schema()


@pytest.fixture
def oid_acl_fixture() -> str:
    """Load OID ACL fixture data."""
    loader = FlextLdifFixtures.OID()
    return loader.acl()


@pytest.fixture
def oid_entries_fixture() -> str:
    """Load OID entries fixture data."""
    loader = FlextLdifFixtures.OID()
    return loader.entries()


@pytest.fixture
def oid_integration_fixture() -> str:
    """Load OID integration fixture data."""
    loader = FlextLdifFixtures.OID()
    return loader.integration()


@pytest.fixture
def oid_schema_entries(
    api: ldif,
    oid_schema_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OID schema fixture into Entry models."""
    result = api.parse_ldif(oid_schema_fixture)
    assert result.is_success, f"OID schema parsing failed: {result.error}"
    return result.value


@pytest.fixture
def oid_entries(api: ldif, oid_entries_fixture: str) -> Sequence[m.Ldif.Entry]:
    """Parse OID entries fixture into Entry models."""
    result = api.parse_ldif(oid_entries_fixture)
    assert result.is_success, f"OID entries parsing failed: {result.error}"
    return result.value


@pytest.fixture
def oud_schema_fixture() -> str:
    """Load OUD schema fixture data."""
    loader = FlextLdifFixtures.OUD()
    return loader.schema()


@pytest.fixture
def oud_acl_fixture() -> str:
    """Load OUD ACL fixture data."""
    loader = FlextLdifFixtures.OUD()
    return loader.acl()


@pytest.fixture
def oud_entries_fixture() -> str:
    """Load OUD entries fixture data."""
    loader = FlextLdifFixtures.OUD()
    return loader.entries()


@pytest.fixture
def oud_integration_fixture() -> str:
    """Load OUD integration fixture data."""
    loader = FlextLdifFixtures.OUD()
    return loader.integration()


@pytest.fixture
def oud_schema_entries(
    api: ldif,
    oud_schema_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OUD schema fixture into Entry models."""
    result = api.parse_ldif(oud_schema_fixture)
    assert result.is_success, f"OUD schema parsing failed: {result.error}"
    return result.value


@pytest.fixture
def oud_entries(api: ldif, oud_entries_fixture: str) -> Sequence[m.Ldif.Entry]:
    """Parse OUD entries fixture into Entry models."""
    result = api.parse_ldif(oud_entries_fixture)
    assert result.is_success, f"OUD entries parsing failed: {result.error}"
    return result.value


@pytest.fixture
def openldap_schema_fixture() -> str:
    """Load OpenLDAP schema fixture data."""
    loader = FlextLdifFixtures.OpenLDAP()
    return loader.schema()


@pytest.fixture
def openldap_acl_fixture() -> str:
    """Load OpenLDAP ACL fixture data."""
    loader = FlextLdifFixtures.OpenLDAP()
    return loader.acl()


@pytest.fixture
def openldap_entries_fixture() -> str:
    """Load OpenLDAP entries fixture data."""
    loader = FlextLdifFixtures.OpenLDAP()
    return loader.entries()


@pytest.fixture
def openldap_integration_fixture() -> str:
    """Load OpenLDAP integration fixture data."""
    loader = FlextLdifFixtures.OpenLDAP()
    return loader.integration()


@pytest.fixture
def openldap_schema_entries(
    api: ldif,
    openldap_schema_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OpenLDAP schema fixture into Entry models."""
    result = api.parse_ldif(openldap_schema_fixture)
    assert result.is_success, f"OpenLDAP schema parsing failed: {result.error}"
    return result.value


@pytest.fixture
def openldap_entries(
    api: ldif,
    openldap_entries_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OpenLDAP entries fixture into Entry models."""
    result = api.parse_ldif(openldap_entries_fixture)
    assert result.is_success, f"OpenLDAP entries parsing failed: {result.error}"
    return result.value


@pytest.fixture
def rfc_schema_fixture() -> str:
    """Load RFC reference schema fixture data."""
    loader = FlextLdifFixtures.RFC()
    return loader.schema()


@pytest.fixture
def rfc_schema_entries(
    api: ldif,
    rfc_schema_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse RFC schema fixture into Entry models."""
    result = api.parse_ldif(rfc_schema_fixture)
    assert result.is_success, f"RFC schema parsing failed: {result.error}"
    return result.value


@pytest.fixture
def all_schema_fixtures() -> Mapping[str, str]:
    """Provide all schema fixtures by server type."""
    return {
        "oid": FlextLdifFixtures.OID().schema(),
        "oud": FlextLdifFixtures.OUD().schema(),
        "openldap": FlextLdifFixtures.OpenLDAP().schema(),
        "rfc": FlextLdifFixtures.RFC().schema(),
    }


@pytest.fixture
def all_entries_fixtures() -> Mapping[str, str]:
    """Provide all entries fixtures by server type."""
    return {
        "oid": FlextLdifFixtures.OID().entries(),
        "oud": FlextLdifFixtures.OUD().entries(),
        "openldap": FlextLdifFixtures.OpenLDAP().entries(),
    }


@pytest.fixture
def all_acl_fixtures() -> Mapping[str, str]:
    """Provide all ACL fixtures by server type."""
    return {
        "oid": FlextLdifFixtures.OID().acl(),
        "oud": FlextLdifFixtures.OUD().acl(),
        "openldap": FlextLdifFixtures.OpenLDAP().acl(),
    }


@pytest.fixture
def all_integration_fixtures() -> Mapping[str, str]:
    """Provide all integration fixtures by server type."""
    return {
        "oid": FlextLdifFixtures.OID().integration(),
        "oud": FlextLdifFixtures.OUD().integration(),
        "openldap": FlextLdifFixtures.OpenLDAP().integration(),
    }


@pytest.fixture
def tmp_ldif_path(tmp_path: Path) -> Path:
    """Create temporary LDIF file path."""
    return tmp_path / "test_output.ldif"


@pytest.fixture
def fixtures_dir() -> Path:
    """Get path to fixtures directory."""
    return Path(__file__).parent.parent / "fixtures"


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
def oid_schema_quirk(oid_quirk: FlextLdifServersBase) -> FlextLdifServersBaseSchema:
    """Create OID schema quirk instance for conversion tests."""
    return oid_quirk.schema_quirk


@pytest.fixture
def oud_schema_quirk(oud_quirk: FlextLdifServersBase) -> FlextLdifServersBaseSchema:
    """Create OUD schema quirk instance for conversion tests."""
    return oud_quirk.schema_quirk


@pytest.fixture
def oid_acl_quirk(oid_quirk: FlextLdifServersBase) -> FlextLdifServersBaseSchemaAcl:
    """Create OID ACL quirk instance for conversion tests."""
    return oid_quirk.acl_quirk


@pytest.fixture
def oud_acl_quirk(oud_quirk: FlextLdifServersBase) -> FlextLdifServersBaseSchemaAcl:
    """Create OUD ACL quirk instance for conversion tests."""
    return oud_quirk.acl_quirk


@pytest.fixture(scope="session")
def ldap_container(worker_id: str) -> t.ContainerMapping:
    """Ensure shared OpenLDAP container is available for integration tests.

    Uses centralized infrastructure: c.Ldif.Docker for constants,
    u.Ldif.Tests.FileLock for locking, u.Ldif.Tests.get_admin_credentials
    for credential resolution.
    """
    docker_control = u.Ldif.Tests.get_docker_control(worker_id)
    server_url = f"ldap://localhost:{_D.PORT}"
    lock = u.Ldif.Tests.FileLock(
        Path.home() / ".flext" / f"{_D.CONTAINER_NAME}.lock",
    )
    with lock:
        start_result = docker_control.start_existing_container(_D.CONTAINER_NAME)
        if start_result.is_failure:
            compose_file = str(WORKSPACE_ROOT / _D.COMPOSE_FILE_REL)
            compose_result = docker_control.compose_up(
                compose_file,
                _D.SERVICE_NAME,
            )
            if compose_result.is_failure:
                pytest.skip(
                    f"Could not start shared OpenLDAP container: {compose_result.error}",
                )
        port_result = docker_control.wait_for_port_ready("localhost", _D.PORT, 15)
        if port_result.is_failure or not port_result.value:
            pytest.skip(f"LDAP container port {_D.PORT} is not ready")
        admin_dn, admin_password = u.Ldif.Tests.get_admin_credentials()
        # Verify LDAP bind readiness
        waited = 0.0
        max_wait = 10.0
        while waited < max_wait:
            try:
                srv = ldap_u.Ldap.create_server_from_url(server_url)
                conn = ldap_u.Ldap.create_connection(
                    srv,
                    user=admin_dn,
                    password=admin_password,
                    auto_bind=False,
                )
                bound: bool = bool(conn.bind())
                if bound:
                    conn.unbind()
                    break
                conn.unbind()
            except (
                ldap_u.Ldap.LDAPException,
                ConnectionError,
                TimeoutError,
                OSError,
            ):
                pass
            time.sleep(1.0)
            waited += 1.0
        else:
            pytest.skip("LDAP container is running but bind is not ready")
    return {
        "server_url": server_url,
        "host": "localhost",
        "bind_dn": admin_dn,
        "password": admin_password,
        "base_dn": _D.BASE_DN,
        "port": _D.PORT,
        "use_ssl": False,
        "worker_id": worker_id,
    }


@pytest.fixture(scope="session")
def ldap_container_shared(ldap_container: t.ContainerMapping) -> str:
    """Provide LDAP connection URL for tests requiring Docker container."""
    default_url = f"ldap://localhost:{_D.PORT}"
    return str(ldap_container.get("server_url", default_url))


@pytest.fixture
def unique_dn_suffix(worker_id: str, request: pytest.FixtureRequest) -> str:
    """Build a unique suffix for LDAP DNs per test execution."""
    node = getattr(request, "node", None)
    test_name: str = (
        str(getattr(node, "name", "unknown")) if node is not None else "unknown"
    )
    test_name_clean: str = "".join(
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

    def _make(ou: str) -> str:
        return f"ou={ou}-{unique_dn_suffix},{_D.BASE_DN}"

    return _make


@pytest.fixture
def ldap_connection(
    ldap_container: t.ContainerMapping,
) -> Generator[p.Ldap.Ldap3Connection]:
    """Provide a bound LDAP connection or skip when unavailable."""
    server_url = str(
        ldap_container.get("server_url", f"ldap://localhost:{_D.PORT}"),
    )
    bind_dn = str(ldap_container.get("bind_dn", _D.ADMIN_DN))
    password = str(ldap_container.get("password", _D.ADMIN_PASSWORD))
    srv = ldap_u.Ldap.create_server_from_url(server_url)
    conn = ldap_u.Ldap.create_connection(
        srv,
        user=bind_dn,
        password=password,
        auto_bind=False,
    )
    try:
        bind_ok: bool = bool(conn.bind())
        if not bind_ok:
            pytest.skip(
                f"LDAP server not available at {server_url} for bind_dn={bind_dn}",
            )
    except (
        ldap_u.Ldap.LDAPException,
        ConnectionError,
        TimeoutError,
        OSError,
    ) as exc:
        pytest.skip(f"LDAP server not available: {exc}")
    yield conn
    conn.unbind()


@pytest.fixture
def clean_test_ou(
    ldap_connection: p.Ldap.Ldap3Connection,
    make_test_base_dn: Callable[[str], str],
) -> Generator[str]:
    """Create and clean up an isolated OU for integration tests."""
    test_ou_dn = make_test_base_dn("FlextLdifTests")
    with contextlib.suppress(Exception):
        ldap_connection.search(test_ou_dn, "(objectClass=*)", search_scope="SUBTREE")
        entries: Sequence[p.Ldap.Ldap3Entry] = list(ldap_connection.entries)
        if entries:
            dns_to_delete: Sequence[str] = [str(entry.entry_dn) for entry in entries]
            for dn in reversed(dns_to_delete):
                with contextlib.suppress(Exception):
                    ldap_connection.delete(dn)
    with contextlib.suppress(Exception):
        ldap_connection.add(
            test_ou_dn,
            ["organizationalUnit"],
            {"ou": "FlextLdifTests"},
        )
    yield test_ou_dn
    with contextlib.suppress(Exception):
        ldap_connection.search(test_ou_dn, "(objectClass=*)", search_scope="SUBTREE")
        entries2: Sequence[p.Ldap.Ldap3Entry] = list(ldap_connection.entries)
        if entries2:
            dns_to_delete2: Sequence[str] = [str(entry.entry_dn) for entry in entries2]
            for dn in reversed(dns_to_delete2):
                with contextlib.suppress(Exception):
                    ldap_connection.delete(dn)
