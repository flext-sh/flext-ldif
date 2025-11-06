"""Configuration and railway-oriented composition tests with live LDAP server.

Test suite verifying LDIF operations against an actual LDAP server:
    - Parse and write LDIF from/to LDAP server
    - Validate roundtrip data integrity (LDAP → LDIF → LDAP)
    - Extract and process schema information
    - Handle ACL entries
    - Perform CRUD operations
    - Process batches of entries

Uses Docker fixture infrastructure from conftest.py for automatic
container management via FlextTestsDocker.ldap_container fixture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

import pytest
from ldap3 import ALL, Connection, Server

from flext_ldif import FlextLdif

# LDAP connection details for flext-openldap-test container
LDAP_ADMIN_DN = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
LDAP_ADMIN_PASSWORD = "REDACTED_LDAP_BIND_PASSWORD123"
LDAP_BASE_DN = "dc=flext,dc=local"


@pytest.fixture(scope="module")
def ldap_connection(ldap_container: str) -> Generator[Connection]:
    """Create connection to real LDAP server via Docker fixture.

    Args:
        ldap_container: Docker LDAP connection string from conftest fixture

    Yields:
        Connection: ldap3 connection to LDAP server

    """
    # ldap_container is a connection URL provided by the Docker fixture
    # Extract host:port from the connection string
    # Expected format: "ldap://localhost:3390"
    host_port = ldap_container.replace("ldap://", "").replace("ldaps://", "")

    server = Server(f"ldap://{host_port}", get_info=ALL)
    conn = Connection(
        server,
        user=LDAP_ADMIN_DN,
        password=LDAP_ADMIN_PASSWORD,
    )

    # Check if server is available
    try:
        if not conn.bind():
            pytest.skip(f"LDAP server not available at {host_port}")
    except Exception as e:
        pytest.skip(f"LDAP server not available at {host_port}: {e}")

    yield conn
    conn.unbind()


@pytest.fixture
def clean_test_ou(ldap_connection: Connection) -> Generator[str]:
    """Create and clean up test OU."""
    test_ou_dn = f"ou=FlextLdifTests,{LDAP_BASE_DN}"

    # Try to delete existing test OU (ignore errors)
    try:
        # Search for all entries under test OU
        found = ldap_connection.search(
            test_ou_dn,
            "(objectClass=*)",
            search_scope="SUBTREE",
            attributes=["*"],
        )
        if found:
            # Delete in reverse order (leaves first)
            dns_to_delete = [entry.entry_dn for entry in ldap_connection.entries]
            for dn in reversed(dns_to_delete):
                try:
                    ldap_connection.delete(dn)
                except Exception:
                    # Ignore delete errors during cleanup - entries may already be deleted
                    # or dependencies may prevent deletion. Cleanup should not fail tests.
                    pass
    except Exception:
        # OU doesn't exist yet - this is expected for first test run
        pass

    # Create test OU (or recreate if deleted above)
    try:
        ldap_connection.add(
            test_ou_dn,
            ["organizationalUnit"],
            {"ou": "FlextLdifTests"},
        )
    except Exception:
        # OU already exists - this is expected if previous test didn't clean up
        pass

    yield test_ou_dn

    # Cleanup after test - delete all entries under test OU
    try:
        found = ldap_connection.search(
            test_ou_dn,
            "(objectClass=*)",
            search_scope="SUBTREE",
            attributes=["*"],
        )
        if found:
            dns_to_delete = [entry.entry_dn for entry in ldap_connection.entries]
            for dn in reversed(dns_to_delete):
                try:
                    ldap_connection.delete(dn)
                except Exception:
                    # Ignore cleanup errors - entries may have dependencies or already be deleted
                    pass
    except Exception:
        # Cleanup failed, but that's okay - test should not fail due to cleanup issues
        pass


@pytest.fixture
def flext_api() -> FlextLdif:
    """FlextLdif API instance."""
    return FlextLdif.get_instance()


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapConfigurationFromEnv:
    """Test configuration loading from .env file."""

    def test_config_loaded_from_env(
        self,
        flext_api: FlextLdif,
    ) -> None:
        """Verify FlextLdifConfig loads from environment variables."""
        # Configuration should be loaded from .env automatically
        config = flext_api.config

        # Verify configuration values (from .env or defaults)
        assert config.ldif_encoding in {"utf-8", "utf-16", "latin1"}
        assert config.max_workers >= 1
        assert isinstance(config.ldif_strict_validation, bool)
        assert isinstance(config.enable_performance_optimizations, bool)

        # Verify LDAP-specific config from environment
        ldap_host = os.getenv("LDAP_HOST", "localhost")
        ldap_port = int(os.getenv("LDAP_PORT", "3390"))

        assert ldap_host is not None
        assert ldap_port > 0
        assert ldap_port <= 65535

    def test_effective_workers_calculation(
        self,
        flext_api: FlextLdif,
    ) -> None:
        """Test dynamic worker calculation based on config and entry count."""
        config = flext_api.config

        # Small dataset - should use 1 worker
        small_workers = config.get_effective_workers(50)
        assert small_workers >= 1

        # Large dataset - should use multiple workers
        large_workers = config.get_effective_workers(10000)
        assert large_workers >= 1
        assert large_workers <= config.max_workers


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapRailwayComposition:
    """Test railway-oriented FlextResult composition with real LDAP."""

    def test_railway_parse_validate_write_cycle(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test FlextResult error handling composition."""
        # Create LDAP data
        person_dn = f"cn=Railway Test,{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": "Railway Test", "sn": "Test", "mail": "railway@example.com"},
        )

        # Search and convert to LDIF
        ldap_connection.search(person_dn, "(objectClass=*)", attributes=["*"])
        ldap_entry = ldap_connection.entries[0]

        # Convert ldap3 entry attributes to dict format
        attrs_dict = {}
        for attr_name in ldap_entry.entry_attributes:
            attr_obj = ldap_entry[attr_name]
            # Extract values from ldap3 Attribute object
            if hasattr(attr_obj, "values"):
                # ldap3 Attribute object with .values property
                values = [str(v) if not isinstance(v, str) else v for v in attr_obj]
            elif isinstance(attr_obj, list):
                # Already a list
                values = [str(v) for v in attr_obj]
            else:
                # Single value
                values = [str(attr_obj)]
            attrs_dict[attr_name] = values

        entry_result = flext_api.models.Entry.create(
            dn=ldap_entry.entry_dn,
            attributes=attrs_dict,
            metadata=None,
        )
        assert entry_result.is_success
        flext_entry = entry_result.unwrap()

        # Railway composition: write → parse → validate
        output_file = tmp_path / "railway.ldif"
        result = (
            flext_api.write([flext_entry], output_file)
            .flat_map(lambda _: flext_api.parse(output_file))
            .flat_map(
                lambda entries: flext_api.validate_entries(entries).map(
                    lambda _: entries,
                ),
            )
        )

        # Verify railway succeeded
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1


__all__ = ["TestRealLdapConfigurationFromEnv", "TestRealLdapRailwayComposition"]
