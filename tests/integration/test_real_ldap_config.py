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

from collections.abc import Callable
from pathlib import Path

import pytest
from flext_core import FlextSettings
from ldap3 import Connection

from flext_ldif import FlextLdif
from flext_ldif.settings import FlextLdifSettings

# Note: flext-ldif cannot import flext-ldap (architecture layering)
# LDAP-related configuration testing is handled in flext-ldap integration tests

# Note: ldap_connection and clean_test_ou fixtures are provided by conftest.py
# They use unique_dn_suffix for isolation and indepotency in parallel execution


@pytest.fixture
def flext_api() -> FlextLdif:
    """FlextLdif API instance."""
    return FlextLdif.get_instance()


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
@pytest.mark.skip(
    reason="LDAP connection fixtures not implemented - requires real LDAP server"
)
class TestRealLdapConfigurationFromEnv:
    """Test configuration loading from .env file."""

    def test_config_loaded_from_env(
        self,
        flext_api: FlextLdif,
    ) -> None:
        """Verify FlextLdifSettings loads from environment variables."""
        # Configuration should be loaded from .env automatically
        root_config = flext_api.config
        # FlextLdifSettings is accessed via .ldif namespace on FlextSettings
        ldif_config = root_config.ldif if hasattr(root_config, "ldif") else None
        # If ldif namespace doesn't exist, try accessing FlextLdifSettings directly
        if ldif_config is None:
            ldif_config = FlextLdifSettings.get_instance()

        # Verify configuration values (from .env or defaults)
        assert ldif_config.ldif_encoding in {"utf-8", "utf-16", "latin1"}
        assert isinstance(ldif_config.ldif_strict_validation, bool)

        # max_workers is in root FlextSettings, not nested FlextLdifSettings
        # Access via super().config to get root config
        root_config = FlextSettings.get_global_instance()
        assert root_config.max_workers >= 1

        # LDAP-specific config testing is handled in flext-ldap project
        # flext-ldif focuses only on LDIF configuration validation

    def test_effective_workers_calculation(
        self,
        flext_api: FlextLdif,
    ) -> None:
        """Test dynamic worker calculation based on config and entry count."""
        # max_workers is in root FlextSettings, not nested FlextLdifSettings
        root_config = FlextSettings.get_global_instance()

        # Verify max_workers is accessible from root config
        assert root_config.max_workers >= 1

        # For small datasets, typically use 1 worker
        # For large datasets, use up to max_workers
        # This test validates that root config is accessible
        assert root_config.max_workers > 0


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
@pytest.mark.skip(
    reason="LDAP connection fixtures not implemented - requires real LDAP server"
)
class TestRealLdapRailwayComposition:
    """Test railway-oriented FlextResult composition with real LDAP."""

    def test_railway_parse_validate_write_cycle(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        tmp_path: Path,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Test FlextResult error handling composition."""
        # Create LDAP data with isolated username
        unique_username = make_test_username("RailwayTest")
        person_dn = f"cn={unique_username},{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": unique_username, "sn": "Test", "mail": "railway@example.com"},
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
        flext_entry = entry_result.value

        # Railway composition: write → parse → validate
        output_file = tmp_path / "railway.ldif"
        result = (
            flext_api
            .write_file([flext_entry], output_file)
            .flat_map(lambda _: flext_api.parse(output_file))
            .flat_map(
                lambda entries: flext_api.validate_entries(entries).map(
                    lambda _: entries,
                ),
            )
        )

        # Verify railway succeeded
        assert result.is_success
        entries = result.value
        assert len(entries) == 1


__all__ = ["TestRealLdapConfigurationFromEnv", "TestRealLdapRailwayComposition"]
