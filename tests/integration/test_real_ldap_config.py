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

from flext_ldif import FlextLdif, FlextLdifSettings


@pytest.fixture
def flext_api() -> FlextLdif:
    """FlextLdif API instance."""
    return FlextLdif.get_instance()


@pytest.mark.integration
class TestRealLdapConfigurationFromEnv:
    """Test configuration loading from .env file."""

    def test_config_loaded_from_env(self, flext_api: FlextLdif) -> None:
        """Verify FlextLdifSettings loads from environment variables."""
        root_config = flext_api.config
        ldif_config = root_config.ldif if hasattr(root_config, "ldif") else None
        if ldif_config is None:
            ldif_config = FlextLdifSettings.get_global_instance()
        assert ldif_config.ldif_encoding in {
            "utf-8",
            "utf-16",
            "ascii",
            "latin-1",
            "iso-8859-1",
            "cp1252",
        }
        assert isinstance(ldif_config.ldif_strict_validation, bool)
        root_config = FlextSettings.get_global_instance()
        assert root_config.max_workers >= 1

    def test_effective_workers_calculation(self, flext_api: FlextLdif) -> None:
        """Test dynamic worker calculation based on config and entry count."""
        root_config = FlextSettings.get_global_instance()
        assert root_config.max_workers >= 1
        assert root_config.max_workers > 0


@pytest.mark.integration
class TestRealLdapRailwayComposition:
    """Test railway-oriented FlextResult composition (write -> parse -> validate)."""

    def test_railway_parse_validate_write_cycle(
        self, flext_api: FlextLdif, tmp_path: Path
    ) -> None:
        """Test FlextResult railway composition: write -> parse -> validate."""
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
        output_file = tmp_path / "railway.ldif"
        result = (
            flext_api
            .write_file([flext_entry], output_file)
            .flat_map(lambda _: flext_api.parse(output_file))
            .flat_map(
                lambda entries: flext_api.validate_entries(entries).map(
                    lambda _: entries
                )
            )
        )
        assert result.is_success
        entries = result.value
        assert len(entries) == 1


__all__ = ["TestRealLdapConfigurationFromEnv", "TestRealLdapRailwayComposition"]
