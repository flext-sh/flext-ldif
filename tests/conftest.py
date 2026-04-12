"""Test configuration and fixtures for flext-ldif tests.

Tests LDIF processing operations: parsing, writing, migration, validation.
Uses factories for data generation, helpers for assertions, and constants for configuration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import contextlib
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
    return u.Ldif.Tests.create_real_entry()


@pytest.fixture
def real_ldif_content() -> str:
    """Provide real LDIF content for testing."""
    return u.Ldif.Tests.create_real_ldif_content()


@pytest.fixture(params=u.Ldif.Tests.parametrize_real_data())
def parametrized_real_data(
    request: pytest.FixtureRequest,
) -> m.Ldif.Tests.LdifTestData:
    """Provide parametrized real test data."""
    return request.param


@pytest.fixture
def large_test_dataset() -> str:
    """Provide large dataset for performance testing."""
    return u.Ldif.Tests.create_real_ldif_content(entries_count=100)


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


@pytest.fixture
def oid_schema_fixture() -> str:
    """Load OID schema fixture data."""
    return u.Ldif.Tests.load_fixture(c.Ldif.Tests.OID, c.Ldif.Tests.SCHEMA)


@pytest.fixture
def oid_acl_fixture() -> str:
    """Load OID ACL fixture data."""
    return u.Ldif.Tests.load_fixture(c.Ldif.Tests.OID, c.Ldif.Tests.ACL)


@pytest.fixture
def oid_entries_fixture() -> str:
    """Load OID entries fixture data."""
    return u.Ldif.Tests.load_fixture(c.Ldif.Tests.OID, c.Ldif.Tests.ENTRIES)


@pytest.fixture
def oid_integration_fixture() -> str:
    """Load OID integration fixture data."""
    return u.Ldif.Tests.load_fixture(
        c.Ldif.Tests.OID,
        c.Ldif.Tests.INTEGRATION,
    )


@pytest.fixture
def oid_schema_entries(
    api: FlextLdif,
    oid_schema_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OID schema fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.expect_success(
        api.parse_ldif(oid_schema_fixture),
        message="OID schema parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def oid_entries(
    api: FlextLdif,
    oid_entries_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OID entries fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.expect_success(
        api.parse_ldif(oid_entries_fixture),
        message="OID entries parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def oud_schema_fixture() -> str:
    """Load OUD schema fixture data."""
    return u.Ldif.Tests.load_fixture(c.Ldif.Tests.OUD, c.Ldif.Tests.SCHEMA)


@pytest.fixture
def oud_acl_fixture() -> str:
    """Load OUD ACL fixture data."""
    return u.Ldif.Tests.load_fixture(c.Ldif.Tests.OUD, c.Ldif.Tests.ACL)


@pytest.fixture
def oud_entries_fixture() -> str:
    """Load OUD entries fixture data."""
    return u.Ldif.Tests.load_fixture(c.Ldif.Tests.OUD, c.Ldif.Tests.ENTRIES)


@pytest.fixture
def oud_integration_fixture() -> str:
    """Load OUD integration fixture data."""
    return u.Ldif.Tests.load_fixture(
        c.Ldif.Tests.OUD,
        c.Ldif.Tests.INTEGRATION,
    )


@pytest.fixture
def oud_schema_entries(
    api: FlextLdif,
    oud_schema_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OUD schema fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.expect_success(
        api.parse_ldif(oud_schema_fixture),
        message="OUD schema parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def oud_entries(
    api: FlextLdif,
    oud_entries_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OUD entries fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.expect_success(
        api.parse_ldif(oud_entries_fixture),
        message="OUD entries parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def openldap_schema_fixture() -> str:
    """Load OpenLDAP schema fixture data."""
    return u.Ldif.Tests.load_fixture(
        c.Ldif.Tests.OPENLDAP,
        c.Ldif.Tests.SCHEMA,
    )


@pytest.fixture
def openldap_acl_fixture() -> str:
    """Load OpenLDAP ACL fixture data."""
    return u.Ldif.Tests.load_fixture(c.Ldif.Tests.OPENLDAP, c.Ldif.Tests.ACL)


@pytest.fixture
def openldap_entries_fixture() -> str:
    """Load OpenLDAP entries fixture data."""
    return u.Ldif.Tests.load_fixture(
        c.Ldif.Tests.OPENLDAP,
        c.Ldif.Tests.ENTRIES,
    )


@pytest.fixture
def openldap_integration_fixture() -> str:
    """Load OpenLDAP integration fixture data."""
    return u.Ldif.Tests.load_fixture(
        c.Ldif.Tests.OPENLDAP,
        c.Ldif.Tests.INTEGRATION,
    )


@pytest.fixture
def openldap_schema_entries(
    api: FlextLdif,
    openldap_schema_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OpenLDAP schema fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.expect_success(
        api.parse_ldif(openldap_schema_fixture),
        message="OpenLDAP schema parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def openldap_entries(
    api: FlextLdif,
    openldap_entries_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse OpenLDAP entries fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.expect_success(
        api.parse_ldif(openldap_entries_fixture),
        message="OpenLDAP entries parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def rfc_schema_fixture() -> str:
    """Load RFC reference schema fixture data."""
    return u.Ldif.Tests.load_fixture(c.Ldif.Tests.RFC, c.Ldif.Tests.SCHEMA)


@pytest.fixture
def rfc_schema_entries(
    api: FlextLdif,
    rfc_schema_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse RFC schema fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.expect_success(
        api.parse_ldif(rfc_schema_fixture),
        message="RFC schema parsing failed",
    )
    return parse_response.entries


@pytest.fixture
def all_schema_fixtures() -> t.StrMapping:
    """Provide all schema fixtures by server type."""
    return {
        c.Ldif.Tests.OID: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.OID,
            c.Ldif.Tests.SCHEMA,
        ),
        c.Ldif.Tests.OUD: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.OUD,
            c.Ldif.Tests.SCHEMA,
        ),
        c.Ldif.Tests.OPENLDAP: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.OPENLDAP,
            c.Ldif.Tests.SCHEMA,
        ),
        c.Ldif.Tests.RFC: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.RFC,
            c.Ldif.Tests.SCHEMA,
        ),
    }


@pytest.fixture
def all_entries_fixtures() -> t.StrMapping:
    """Provide all entries fixtures by server type."""
    return {
        c.Ldif.Tests.OID: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.OID,
            c.Ldif.Tests.ENTRIES,
        ),
        c.Ldif.Tests.OUD: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.OUD,
            c.Ldif.Tests.ENTRIES,
        ),
        c.Ldif.Tests.OPENLDAP: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.OPENLDAP,
            c.Ldif.Tests.ENTRIES,
        ),
    }


@pytest.fixture
def all_acl_fixtures() -> t.StrMapping:
    """Provide all ACL fixtures by server type."""
    return {
        c.Ldif.Tests.OID: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.OID,
            c.Ldif.Tests.ACL,
        ),
        c.Ldif.Tests.OUD: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.OUD,
            c.Ldif.Tests.ACL,
        ),
        c.Ldif.Tests.OPENLDAP: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.OPENLDAP,
            c.Ldif.Tests.ACL,
        ),
    }


@pytest.fixture
def all_integration_fixtures() -> t.StrMapping:
    """Provide all integration fixtures by server type."""
    return {
        c.Ldif.Tests.OID: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.OID,
            c.Ldif.Tests.INTEGRATION,
        ),
        c.Ldif.Tests.OUD: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.OUD,
            c.Ldif.Tests.INTEGRATION,
        ),
        c.Ldif.Tests.OPENLDAP: u.Ldif.Tests.load_fixture(
            c.Ldif.Tests.OPENLDAP,
            c.Ldif.Tests.INTEGRATION,
        ),
    }


@pytest.fixture
def tmp_ldif_path(tmp_path: Path) -> Path:
    """Create temporary LDIF file path."""
    return tmp_path / "test_output.ldif"


@pytest.fixture
def fixtures_dir() -> Path:
    """Get path to fixtures directory."""
    return c.Ldif.Tests.FIXTURES_DIR


@pytest.fixture
def conversion_matrix() -> FlextLdifConversion:
    """Create FlextLdifConversion instance for conversion tests."""
    return FlextLdifConversion()


@pytest.fixture
def server() -> FlextLdifServer:
    """Get FlextLdifServer instance for quirk management."""
    return FlextLdifServer.get_global_instance()


@pytest.fixture
def oid_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OID server quirk via FlextLdifServer API."""
    return u.expect_success(
        server.quirk("oid"),
        message="OID quirk must be registered",
    )


@pytest.fixture
def oud_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OUD server quirk via FlextLdifServer API."""
    return u.expect_success(
        server.get_base_quirk("oud"),
        message="OUD quirk must be registered",
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
def ldap_container(worker_id: str) -> t.RecursiveContainerMapping:
    """Ensure shared OpenLDAP container is available for integration tests.

    Uses centralized infrastructure: c.Ldif.Tests for constants,
    u.Ldif.Tests.FileLock for locking, u.Ldif.Tests.get_admin_credentials
    for credential resolution.
    """
    docker_control = u.Ldif.Tests.get_docker_control(worker_id)
    server_url = f"ldap://localhost:{c.Ldif.Tests.DOCKER_PORT}"
    lock = u.Ldif.Tests.FileLock(
        Path.home() / ".flext" / f"{c.Ldif.Tests.DOCKER_CONTAINER_NAME}.lock",
    )
    with lock:
        start_result = docker_control.start_existing_container(
            c.Ldif.Tests.DOCKER_CONTAINER_NAME,
        )
        if start_result.failure:
            compose_file = str(
                c.Ldif.Tests.WORKSPACE_ROOT / c.Ldif.Tests.DOCKER_COMPOSE_FILE_REL
            )
            compose_result = docker_control.compose_up(
                compose_file,
                c.Ldif.Tests.DOCKER_SERVICE_NAME,
            )
            if compose_result.failure:
                pytest.skip(
                    f"Could not start shared OpenLDAP container: {compose_result.error}",
                )
        port_result = docker_control.wait_for_port_ready(
            "localhost",
            c.Ldif.Tests.DOCKER_PORT,
            15,
        )
        if port_result.failure or not port_result.value:
            pytest.skip(
                f"LDAP container port {c.Ldif.Tests.DOCKER_PORT} is not ready",
            )
        admin_dn, admin_password = u.Ldif.Tests.get_admin_credentials()
        # Verify LDAP bind readiness
        waited = 0.0
        max_wait = 10.0
        while waited < max_wait:
            try:
                srv = u.Ldif.Tests.create_server_from_url(server_url)
                conn = u.Ldif.Tests.create_connection(
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
                t.Ldap.LDAPException,
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
        "base_dn": c.Ldif.Tests.DOCKER_BASE_DN,
        "port": c.Ldif.Tests.DOCKER_PORT,
        "use_ssl": False,
        "worker_id": worker_id,
    }


@pytest.fixture(scope="session")
def ldap_container_shared(ldap_container: t.RecursiveContainerMapping) -> str:
    """Provide LDAP connection URL for tests requiring Docker container."""
    default_url = f"ldap://localhost:{c.Ldif.Tests.DOCKER_PORT}"
    return str(ldap_container.get("server_url", default_url))


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
        return f"ou={ou}-{unique_dn_suffix},{c.Ldif.Tests.DOCKER_BASE_DN}"

    return _make


@pytest.fixture
def ldap_connection(
    ldap_container: t.RecursiveContainerMapping,
) -> Generator[p.Ldap.Ldap3Connection]:
    """Provide a bound LDAP connection or skip when unavailable."""
    server_url = str(
        ldap_container.get(
            "server_url", f"ldap://localhost:{c.Ldif.Tests.DOCKER_PORT}"
        ),
    )
    bind_dn = str(ldap_container.get("bind_dn", c.Ldif.Tests.DOCKER_ADMIN_DN))
    password = str(
        ldap_container.get("password", c.Ldif.Tests.DOCKER_ADMIN_PASSWORD),
    )
    srv = u.Ldif.Tests.create_server_from_url(server_url)
    conn = u.Ldif.Tests.create_connection(
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
        t.Ldap.LDAPException,
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
            dns_to_delete: t.StrSequence = [str(entry.entry_dn) for entry in entries]
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
            dns_to_delete2: t.StrSequence = [str(entry.entry_dn) for entry in entries2]
            for dn in reversed(dns_to_delete2):
                with contextlib.suppress(Exception):
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
