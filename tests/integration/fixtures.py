"""Shared integration pytest fixtures for flext-ldif tests."""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tests import c, t, u

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from tests import p


def _probe_ldap_bind(server_url: str, admin_dn: str, admin_password: str) -> str | None:
    """Return bind error text, or None when LDAP bind is ready."""
    try:
        srv = u.Tests.create_server_from_url(server_url)
        conn = u.Tests.create_connection(
            srv, user=admin_dn, password=admin_password, auto_bind=False
        )
        bound: bool = conn.bind()
        conn.unbind()
        if bound:
            return None
        return "LDAP bind returned False"
    except (t.Ldap.LDAPException, ConnectionError, TimeoutError, OSError) as exc:
        return str(exc)


@pytest.fixture(scope="session")
def ldap_container(worker_id: str) -> t.JsonMapping:
    """Ensure shared OpenLDAP container is available for integration tests."""
    docker_control = u.Tests.get_docker_control(worker_id)
    server_url = f"ldap://localhost:{c.Tests.DOCKER_PORT}"
    lock = u.Tests.FileLock(
        Path.home() / ".flext" / f"{c.Tests.DOCKER_CONTAINER_NAME}.lock"
    )
    with lock:
        execute_result = docker_control.execute()
        if execute_result.failure:
            pytest.fail(
                f"Could not start shared OpenLDAP container: {execute_result.error}"
            )
        admin_dn, admin_password = u.Tests.get_admin_credentials()
        waited = 0.0
        max_wait = 10.0
        last_error: str | None = None
        while waited < max_wait:
            last_error = _probe_ldap_bind(server_url, admin_dn, admin_password)
            if last_error is None:
                break
            time.sleep(1.0)
            waited += 1.0
        else:
            pytest.fail(
                "LDAP container is running but bind is not ready"
                if last_error is None
                else f"LDAP container bind is not ready: {last_error}"
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
def ldap_connection(ldap_container: t.JsonMapping) -> Generator[p.Ldap.Ldap3Connection]:
    """Provide a bound LDAP connection for integration tests."""
    server_url = str(ldap_container["server_url"])
    bind_dn = str(ldap_container["bind_dn"])
    password = str(ldap_container["password"])
    srv = u.Tests.create_server_from_url(server_url)
    conn = u.Tests.create_connection(
        srv, user=bind_dn, password=password, auto_bind=False
    )
    try:
        bind_ok: bool = conn.bind()
        if not bind_ok:
            pytest.fail(
                f"LDAP server not available at {server_url} for bind_dn={bind_dn}"
            )
    except (t.Ldap.LDAPException, ConnectionError, TimeoutError, OSError) as exc:
        pytest.fail(f"LDAP server not available: {exc}")
    yield conn
    conn.unbind()


@pytest.fixture
def clean_test_ou(
    ldap_connection: p.Ldap.Ldap3Connection, make_test_base_dn: Callable[[str], str]
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
    ldap_connection.add(test_ou_dn, ["organizationalUnit"], {"ou": "FlextLdifTests"})
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
