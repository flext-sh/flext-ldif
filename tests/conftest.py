"""Test configuration and fixtures for flext-ldif tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from collections.abc import (
    Callable,
    Generator,
)
from pathlib import Path

import pytest

from flext_ldif import (
    FlextLdifConversion,
    FlextLdifParser,
    FlextLdifServer,
    FlextLdifWriter,
    ldif,
)
from tests import m, p, t
from tests.constants import TestsFlextLdifConstants, c
from tests.utilities import TestsFlextLdifUtilities as u


@pytest.fixture
def api() -> p.Ldif.LdifClient:
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


@pytest.fixture
def oid_schema_fixture() -> str:
    """Load OID schema fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OID, c.Tests.SCHEMA)
    return fixture_content


@pytest.fixture
def oid_acl_fixture() -> str:
    """Load OID ACL fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OID, c.Tests.ACL)
    return fixture_content


@pytest.fixture
def oid_entries_fixture() -> str:
    """Load OID entries fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OID, c.Tests.ENTRIES)
    return fixture_content


@pytest.fixture
def oid_integration_fixture() -> str:
    """Load OID integration fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OID, c.Tests.INTEGRATION)
    return fixture_content


@pytest.fixture
def oid_entries(
    api: p.Ldif.LdifClient,
    oid_entries_fixture: str,
) -> t.SequenceOf[m.Ldif.Entry]:
    """Parse OID entries fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.Tests.assert_success(
        api.parse_ldif(oid_entries_fixture),
        error_msg="OID entries parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def oud_schema_fixture() -> str:
    """Load OUD schema fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.SCHEMA)
    return fixture_content


@pytest.fixture
def oud_acl_fixture() -> str:
    """Load OUD ACL fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.ACL)
    return fixture_content


@pytest.fixture
def oud_entries_fixture() -> str:
    """Load OUD entries fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.ENTRIES)
    return fixture_content


@pytest.fixture
def oud_integration_fixture() -> str:
    """Load OUD integration fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.INTEGRATION)
    return fixture_content


@pytest.fixture
def oud_entries(
    api: p.Ldif.LdifClient,
    oud_entries_fixture: str,
) -> t.SequenceOf[m.Ldif.Entry]:
    """Parse OUD entries fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.Tests.assert_success(
        api.parse_ldif(oud_entries_fixture),
        error_msg="OUD entries parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def fixtures_dir() -> Path:
    """Get path to fixtures directory."""
    return TestsFlextLdifConstants.Tests.FIXTURES_DIR


@pytest.fixture
def conversion_matrix() -> FlextLdifConversion:
    """Create FlextLdifConversion instance for conversion tests."""
    return FlextLdifConversion()


@pytest.fixture
def server() -> FlextLdifServer:
    """Get FlextLdifServer instance for server management."""
    return FlextLdifServer.fetch_global_instance()


@pytest.fixture
def oid_server(server: FlextLdifServer) -> p.Ldif.ServerServer:
    """Get OID server server via FlextLdifServer API."""
    return u.Tests.assert_success(
        server.server("oid"),
        error_msg="OID server must be registered",
    )


@pytest.fixture
def oud_server(server: FlextLdifServer) -> p.Ldif.ServerServer:
    """Get OUD server server via FlextLdifServer API."""
    return u.Tests.assert_success(
        server.resolve_base_server("oud"),
        error_msg="OUD server must be registered",
    )


@pytest.fixture
def oid_schema_server(
    oid_server: p.Ldif.ServerServer,
) -> p.Ldif.SchemaServer:
    """Create OID schema server instance for conversion tests."""
    return oid_server.schema_server


@pytest.fixture
def oud_schema_server(
    oud_server: p.Ldif.ServerServer,
) -> p.Ldif.SchemaServer:
    """Create OUD schema server instance for conversion tests."""
    return oud_server.schema_server


@pytest.fixture
def oid_acl_server(
    oid_server: p.Ldif.ServerServer,
) -> p.Ldif.AclServer:
    """Create OID ACL server instance for conversion tests."""
    return oid_server.acl_server


@pytest.fixture
def oud_acl_server(
    oud_server: p.Ldif.ServerServer,
) -> p.Ldif.AclServer:
    """Create OUD ACL server instance for conversion tests."""
    return oud_server.acl_server


@pytest.fixture(scope="session")
def ldap_container(worker_id: str) -> t.JsonMapping:
    """Ensure shared OpenLDAP container is available for integration tests."""
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


@pytest.fixture
def unique_dn_suffix(worker_id: str, request: pytest.FixtureRequest) -> str:
    """Build a unique suffix for LDAP DNs per test execution."""
    getattr(request, "node", None)
    test_name: t.StrSequence = ()
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
    entries: t.SequenceOf[p.Ldap.Ldap3Entry] = list(ldap_connection.entries)
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
    entries2: t.SequenceOf[p.Ldap.Ldap3Entry] = list(ldap_connection.entries)
    if entries2:
        dns_to_delete2: t.StrSequence = [str(entry.entry_dn) for entry in entries2]
        for dn in reversed(dns_to_delete2):
            ldap_connection.delete(dn)
