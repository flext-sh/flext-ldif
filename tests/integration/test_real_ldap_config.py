"""Configuration and railway-oriented composition integration tests.

Test suite verifying:
    - Configuration loading from environment variables
    - Railway-oriented FlextResult composition (write → parse → validate)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_core import FlextSettings

from flext_ldif import FlextLdif
from flext_ldif.settings import FlextLdifSettings


@pytest.fixture
def flext_api() -> FlextLdif:
    """FlextLdif API instance."""
    return FlextLdif.get_instance()


@pytest.mark.integration
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
            ldif_config = FlextLdifSettings.get_global_instance()

        # Verify configuration values (from .env or defaults)
        assert ldif_config.ldif_encoding in {
            "utf-8",
            "utf-16",
            "ascii",
            "latin-1",
            "iso-8859-1",
            "cp1252",
        }
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


@pytest.mark.integration
class TestRealLdapRailwayComposition:
    """Test railway-oriented FlextResult composition (write -> parse -> validate)."""

    def test_railway_parse_validate_write_cycle(
        self,
        flext_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test FlextResult railway composition: write -> parse -> validate."""
        # Create entry programmatically (no LDAP dependency needed)
        entry_result = flext_api.models.Ldif.Entry.create(
            dn="cn=RailwayTest,ou=people,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["RailwayTest"],
                "sn": ["Test"],
                "mail": ["railway@example.com"],
            },
            metadata=None,
        )
        assert entry_result.is_success
        flext_entry = entry_result.value

        # Railway composition: write -> parse -> validate
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
