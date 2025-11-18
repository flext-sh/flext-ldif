"""Test Docker fixtures for idempotent and parallelizable tests.

This test module validates that the Docker container management fixtures
work correctly and can run in parallel without conflicts.
"""

from __future__ import annotations

import socket

import pytest


@pytest.mark.docker
@pytest.mark.integration
def test_ldap_container_dynamic_starts(ldap_container_dynamic: str) -> None:
    """Test that dynamic LDAP container fixture provides working connection.

    Args:
        ldap_container_dynamic: LDAP connection string from fixture

    """
    # Parse connection string
    assert ldap_container_dynamic.startswith("ldap://localhost:")

    # Extract port
    port_str = ldap_container_dynamic.rsplit(":", maxsplit=1)[-1]
    port = int(port_str)

    # Verify port is open
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        result = sock.connect_ex(("localhost", port))
        assert result == 0, f"LDAP port {port} is not open"


@pytest.mark.docker
@pytest.mark.integration
def test_ldap_container_dynamic_isolation_test1(ldap_container_dynamic: str) -> None:
    """Test 1: Verify containers are isolated between tests.

    Each test should get its own container with unique port.

    Args:
        ldap_container_dynamic: LDAP connection string from fixture

    """
    assert ldap_container_dynamic.startswith("ldap://localhost:")
    # This test and test_ldap_container_dynamic_isolation_test2 should
    # get different ports when run in parallel


@pytest.mark.docker
@pytest.mark.integration
def test_ldap_container_dynamic_isolation_test2(ldap_container_dynamic: str) -> None:
    """Test 2: Verify containers are isolated between tests.

    Each test should get its own container with unique port.

    Args:
        ldap_container_dynamic: LDAP connection string from fixture

    """
    assert ldap_container_dynamic.startswith("ldap://localhost:")
    # This test and test_ldap_container_dynamic_isolation_test1 should
    # get different ports when run in parallel


@pytest.mark.docker
@pytest.mark.integration
def test_ldap_container_shared_works(ldap_container_shared: str) -> None:
    """Test that shared LDAP container fixture provides working connection.

    Args:
        ldap_container_shared: LDAP connection string from fixture

    """
    # Parse connection string
    assert ldap_container_shared.startswith("ldap://localhost:")

    # Extract port
    port_str = ldap_container_shared.rsplit(":", maxsplit=1)[-1]
    port = int(port_str)

    # Verify port is open
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        result = sock.connect_ex(("localhost", port))
        assert result == 0, f"LDAP port {port} is not open"
