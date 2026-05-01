"""Test configuration and fixtures for flext-ldif tests.

Tests LDIF processing operations: parsing, writing, migration, validation.
Uses factories for data generation, helpers for assertions, and constants for configuration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from collections.abc import (
    Callable,
    Generator,
    Sequence,
)
from pathlib import Path

import pytest

from flext_ldif import (
    FlextLdif,
    FlextLdifConversion,
    FlextLdifParser,
    FlextLdifServer,
    FlextLdifServersBase,
    FlextLdifServersBaseSchema,
    FlextLdifServersBaseSchemaAcl,
    FlextLdifSettings,
    FlextLdifWriter,
    ldif,
)
from tests import c, m, p, t, u


@pytest.fixture
def ldif_settings(
    settings_factory: Callable[..., FlextLdifSettings],
) -> FlextLdifSettings:
    """Provide clean FlextLdifSettings for tests."""
    return settings_factory(FlextLdifSettings)


@pytest.fixture
def real_entry() -> m.Ldif.Entry:
    """Provide a real Entry model for testing."""
    return u.Tests.create_real_entry()


@pytest.fixture
def real_ldif_content() -> str:
    """Provide real LDIF content for testing."""
    return u.Tests.create_real_ldif_content()


@pytest.fixture(params=u.Tests.parametrize_real_data())
def parametrized_real_data(
    request: pytest.FixtureRequest,
) -> m.Tests.LdifTestData:
    """Provide parametrized real test data."""
    return request.param


@pytest.fixture
def large_test_dataset() -> str:
    """Provide large dataset for performance testing."""
    return u.Tests.create_real_ldif_content(entries_count=100)


@pytest.fixture
def api() -> FlextLdif:
    """Create ldif API instance for testing."""
    return ldif()


@pytest.fixture
def parser() -> FlextLdifParser:
    """Create ldif parser service for testing."""
    return FlextLdifParser()


@pytest.fixture
def writer() -> FlextLdifWriter:
    """Create ldif writer service for testing."""
    return FlextLdifWriter()


def _fixtures_for_kind(kind: str) -> t.StrMapping:
    """Build fixture map for one kind using constants-driven server matrix."""
    return {
        server: u.Tests.load(server, kind)
        for server in c.Tests.FIXTURE_KIND_SERVERS[kind]
    }


@pytest.fixture
def oid_schema_fixture() -> str:
    """Load OID schema fixture data."""
    return u.Tests.load(
        c.Tests.OID,
        c.Tests.SCHEMA,
    )


@pytest.fixture
def oid_acl_fixture() -> str:
    """Load OID ACL fixture data."""
    return u.Tests.load(
        c.Tests.OID,
        c.Tests.ACL,
    )


@pytest.fixture
def oid_entries_fixture() -> str:
    """Load OID entries fixture data."""
    return u.Tests.load(c.Tests.OID, c.Tests.ENTRIES)


@pytest.fixture
def oid_integration_fixture() -> str:
    """Load OID integration fixture data."""
    return u.Tests.load(
        c.Tests.OID,
        c.Tests.INTEGRATION,
    )


@pytest.fixture
def oid_schema_entries(
    api: FlextLdif,
    oid_schema_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OID schema fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.Tests.assert_success(
        api.parse_ldif(oid_schema_fixture),
        error_msg="OID schema parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def oid_entries(
    api: FlextLdif,
    oid_entries_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OID entries fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.Tests.assert_success(
        api.parse_ldif(oid_entries_fixture),
        error_msg="OID entries parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def oud_schema_fixture() -> str:
    """Load OUD schema fixture data."""
    return u.Tests.load(c.Tests.OUD, c.Tests.SCHEMA)


@pytest.fixture
def oud_acl_fixture() -> str:
    """Load OUD ACL fixture data."""
    return u.Tests.load(c.Tests.OUD, c.Tests.ACL)


@pytest.fixture
def oud_entries_fixture() -> str:
    """Load OUD entries fixture data."""
    return u.Tests.load(c.Tests.OUD, c.Tests.ENTRIES)


@pytest.fixture
def oud_integration_fixture() -> str:
    """Load OUD integration fixture data."""
    return u.Tests.load(
        c.Tests.OUD,
        c.Tests.INTEGRATION,
    )


@pytest.fixture
def oud_schema_entries(
    api: FlextLdif,
    oud_schema_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OUD schema fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.Tests.assert_success(
        api.parse_ldif(oud_schema_fixture),
        error_msg="OUD schema parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def oud_entries(
    api: FlextLdif,
    oud_entries_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OUD entries fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.Tests.assert_success(
        api.parse_ldif(oud_entries_fixture),
        error_msg="OUD entries parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def openldap_schema_fixture() -> str:
    """Load OpenLDAP schema fixture data."""
    return u.Tests.load(
        c.Tests.OPENLDAP,
        c.Tests.SCHEMA,
    )


@pytest.fixture
def openldap_acl_fixture() -> str:
    """Load OpenLDAP ACL fixture data."""
    return u.Tests.load(c.Tests.OPENLDAP, c.Tests.ACL)


@pytest.fixture
def openldap_entries_fixture() -> str:
    """Load OpenLDAP entries fixture data."""
    return u.Tests.load(
        c.Tests.OPENLDAP,
        c.Tests.ENTRIES,
    )


@pytest.fixture
def openldap_integration_fixture() -> str:
    """Load OpenLDAP integration fixture data."""
    return u.Tests.load(
        c.Tests.OPENLDAP,
        c.Tests.INTEGRATION,
    )


@pytest.fixture
def openldap_schema_entries(
    api: FlextLdif,
    openldap_schema_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OpenLDAP schema fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.Tests.assert_success(
        api.parse_ldif(openldap_schema_fixture),
        error_msg="OpenLDAP schema parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def openldap_entries(
    api: FlextLdif,
    openldap_entries_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OpenLDAP entries fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.Tests.assert_success(
        api.parse_ldif(openldap_entries_fixture),
        error_msg="OpenLDAP entries parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def rfc_schema_fixture() -> str:
    """Load RFC reference schema fixture data."""
    return u.Tests.load(c.Tests.RFC, c.Tests.SCHEMA)


@pytest.fixture
def rfc_schema_entries(
    api: FlextLdif,
    rfc_schema_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse RFC schema fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.Tests.assert_success(
        api.parse_ldif(rfc_schema_fixture),
        error_msg="RFC schema parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def all_schema_fixtures() -> t.StrMapping:
    """Provide all schema fixtures by server type."""
    return _fixtures_for_kind(c.Tests.SCHEMA)


@pytest.fixture
def all_entries_fixtures() -> t.StrMapping:
    """Provide all entries fixtures by server type."""
    return _fixtures_for_kind(c.Tests.ENTRIES)


@pytest.fixture
def all_acl_fixtures() -> t.StrMapping:
    """Provide all ACL fixtures by server type."""
    return _fixtures_for_kind(c.Tests.ACL)


@pytest.fixture
def all_integration_fixtures() -> t.StrMapping:
    """Provide all integration fixtures by server type."""
    return _fixtures_for_kind(c.Tests.INTEGRATION)


@pytest.fixture
def tmp_ldif_path(tmp_path: Path) -> Path:
    """Create temporary LDIF file path."""
    return tmp_path / "test_output.ldif"


@pytest.fixture
def fixtures_dir() -> Path:
    """Get path to fixtures directory."""
    return c.Tests.FIXTURES_DIR


@pytest.fixture
def conversion_matrix() -> FlextLdifConversion:
    """Create FlextLdifConversion instance for conversion tests."""
    return FlextLdifConversion()


@pytest.fixture
def server() -> FlextLdifServer:
    """Get FlextLdifServer instance for quirk management."""
    return FlextLdifServer.fetch_global_instance()


@pytest.fixture
def oid_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OID server quirk via FlextLdifServer API."""
    return u.Tests.assert_success(
        server.quirk("oid"),
        error_msg="OID quirk must be registered",
    )


@pytest.fixture
def oud_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OUD server quirk via FlextLdifServer API."""
    return u.Tests.assert_success(
        server.resolve_base_quirk("oud"),
        error_msg="OUD quirk must be registered",
    )


@pytest.fixture
def oid_schema_quirk(
    oid_quirk: FlextLdifServersBase,
) -> FlextLdifServersBaseSchema:
    """Create OID schema quirk instance for conversion tests."""
    return oid_quirk.schema_quirk


@pytest.fixture
def oud_schema_quirk(
    oud_quirk: FlextLdifServersBase,
) -> FlextLdifServersBaseSchema:
    """Create OUD schema quirk instance for conversion tests."""
    return oud_quirk.schema_quirk


@pytest.fixture
def oid_acl_quirk(
    oid_quirk: FlextLdifServersBase,
) -> FlextLdifServersBaseSchemaAcl:
    """Create OID ACL quirk instance for conversion tests."""
    return oid_quirk.acl_quirk


@pytest.fixture
def oud_acl_quirk(
    oud_quirk: FlextLdifServersBase,
) -> FlextLdifServersBaseSchemaAcl:
    """Create OUD ACL quirk instance for conversion tests."""
    return oud_quirk.acl_quirk


@pytest.fixture(scope="session")
def ldap_container(worker_id: str) -> t.JsonMapping:
    """Ensure shared OpenLDAP container is available for integration tests.

    Uses centralized infrastructure: c.Tests.Tests for constants,
    u.Tests.FileLock for locking, u.Tests.get_admin_credentials
    for credential resolution.
    """
    docker_control = u.Tests.get_docker_control(worker_id)
    server_url = f"ldap://localhost:{c.Tests.DOCKER_PORT}"
    lock = u.Tests.FileLock(
        Path.home() / ".flext" / f"{c.Tests.DOCKER_CONTAINER_NAME}.lock",
    )
    with lock:
        execute_result = docker_control.execute()
        if execute_result.failure:
            pytest.fail(
                f"Could not start shared OpenLDAP container: {execute_result.error}",
            )
        admin_dn, admin_password = u.Tests.get_admin_credentials()
        # Verify LDAP bind readiness
        waited = 0.0
        max_wait = 10.0
        last_error: str | None = None
        while waited < max_wait:
            try:
                srv = u.Tests.create_server_from_url(server_url)
                conn = u.Tests.create_connection(
                    srv,
                    user=admin_dn,
                    password=admin_password,
                    auto_bind=False,
                )
                bound: bool = conn.bind()
                if bound:
                    conn.unbind()
                    break
                conn.unbind()
                last_error = "LDAP bind returned False"
            except (
                t.Ldap.LDAPException,
                ConnectionError,
                TimeoutError,
                OSError,
            ) as exc:
                last_error = str(exc)
            time.sleep(1.0)
            waited += 1.0
        else:
            pytest.fail(
                "LDAP container is running but bind is not ready"
                if last_error is None
                else f"LDAP container bind is not ready: {last_error}",
            )
    return {
        "server_url": server_url,
        "host": "localhost",
        "bind_dn": admin_dn,
        "password": admin_password,
        "base_dn": c.Tests.DOCKER_BASE_DN,
        "port": c.Tests.DOCKER_PORT,
        "use_ssl": False,
        "worker_id": worker_id,
    }


@pytest.fixture(scope="session")
def ldap_container_shared(ldap_container: t.JsonMapping) -> str:
    """Provide LDAP connection URL for tests requiring Docker container."""
    return str(ldap_container["server_url"])


@pytest.fixture
def unique_dn_suffix(worker_id: str, request: pytest.FixtureRequest) -> str:
    """Build a unique suffix for LDAP DNs per test execution."""
    getattr(request, "node", None)
    test_name: tuple[str, ...] = ()
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
        return f"ou={ou}-{unique_dn_suffix},{c.Tests.DOCKER_BASE_DN}"

    return _make


@pytest.fixture
def ldap_connection(
    ldap_container: t.JsonMapping,
) -> Generator[p.Ldap.Ldap3Connection]:
    """Provide a bound LDAP connection for integration tests."""
    server_url = str(ldap_container["server_url"])
    bind_dn = str(ldap_container["bind_dn"])
    password = str(ldap_container["password"])
    srv = u.Tests.create_server_from_url(server_url)
    conn = u.Tests.create_connection(
        srv,
        user=bind_dn,
        password=password,
        auto_bind=False,
    )
    try:
        bind_ok: bool = conn.bind()
        if not bind_ok:
            pytest.fail(
                f"LDAP server not available at {server_url} for bind_dn={bind_dn}",
            )
    except (
        t.Ldap.LDAPException,
        ConnectionError,
        TimeoutError,
        OSError,
    ) as exc:
        pytest.fail(f"LDAP server not available: {exc}")
    yield conn
    conn.unbind()


@pytest.fixture
def clean_test_ou(
    ldap_connection: p.Ldap.Ldap3Connection,
    make_test_base_dn: Callable[[str], str],
) -> Generator[str]:
    """Create and clean up an isolated OU for integration tests."""
    test_ou_dn = make_test_base_dn("FlextLdifTests")
    ldap_connection.search(
        test_ou_dn,
        "(objectClass=*)",
        search_scope=c.Ldap.Ldap3SearchScope.SUBTREE.value,
    )
    entries: Sequence[p.Ldap.Ldap3Entry] = list(ldap_connection.entries)
    if entries:
        dns_to_delete: t.StrSequence = [str(entry.entry_dn) for entry in entries]
        for dn in reversed(dns_to_delete):
            ldap_connection.delete(dn)
    ldap_connection.add(
        test_ou_dn,
        ["organizationalUnit"],
        {"ou": "FlextLdifTests"},
    )
    yield test_ou_dn
    ldap_connection.search(
        test_ou_dn,
        "(objectClass=*)",
        search_scope=c.Ldap.Ldap3SearchScope.SUBTREE.value,
    )
    entries2: Sequence[p.Ldap.Ldap3Entry] = list(ldap_connection.entries)
    if entries2:
        dns_to_delete2: t.StrSequence = [str(entry.entry_dn) for entry in entries2]
        for dn in reversed(dns_to_delete2):
            ldap_connection.delete(dn)


def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: marks tests as unit tests")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "ldif: marks tests as LDIF-specific tests")
    config.addinivalue_line("markers", "docker: marks tests that require Docker")
    config.addinivalue_line("markers", "slow: marks tests as slow tests")
    config.addinivalue_line("markers", "real: marks tests using real functionality")


@pytest.fixture(scope="session")
def flext_ldif() -> FlextLdif:
    """Provide ldif instance for tests."""
    return ldif()
