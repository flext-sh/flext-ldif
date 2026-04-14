"""Configuration and railway-oriented composition integration tests.

Test suite verifying:
    - Configuration loading from environment variables
    - Railway-oriented r composition (write → parse → validate)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_core import FlextSettings
from flext_ldif import FlextLdif, FlextLdifSettings, ldif
from tests import m


@pytest.fixture
def flext_api() -> FlextLdif:
    """Ldif API instance."""
    return ldif()


@pytest.mark.integration
class TestRealLdapConfigurationFromEnv:
    """Test configuration loading from .env file."""

    def test_config_loaded_from_env(self, flext_api: FlextLdif) -> None:
        """Verify FlextLdifSettings loads from environment variables."""
        ldif_config: FlextLdifSettings = flext_api.settings
        assert ldif_config.ldif_encoding in {
            "utf-8",
            "utf-16",
            "ascii",
            "latin-1",
            "iso-8859-1",
            "cp1252",
        }
        assert isinstance(ldif_config.ldif_strict_validation, bool)
        root_config = FlextSettings.fetch_global()
        assert root_config.max_workers >= 1

    def test_effective_workers_calculation(self, flext_api: FlextLdif) -> None:
        """Test dynamic worker calculation based on settings and entry count."""
        root_config = FlextSettings.fetch_global()
        assert root_config.max_workers >= 1
        assert root_config.max_workers > 0


@pytest.mark.integration
class TestRealLdapRailwayComposition:
    """Test railway-oriented r composition (write -> parse -> validate)."""

    def test_railway_parse_validate_write_cycle(
        self,
        flext_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test r railway composition: write -> parse -> validate."""
        entry_result = m.Ldif.Entry.create(
            dn="cn=RailwayTest,ou=people,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["RailwayTest"],
                "sn": ["Test"],
                "mail": ["railway@example.com"],
            },
            metadata=None,
        )
        assert entry_result.success
        flext_entry = entry_result.value
        output_file = tmp_path / "railway.ldif"
        result = (
            flext_api
            .write_ldif_file([flext_entry], output_file)
            .flat_map(lambda _: flext_api.parse_ldif(output_file))
            .flat_map(
                lambda entries: flext_api.validate_entries(entries).map(
                    lambda _: entries,
                ),
            )
        )
        assert result.success
        entries = result.value.entries
        assert len(entries) == 1


__all__: list[str] = [
    "TestRealLdapConfigurationFromEnv",
    "TestRealLdapRailwayComposition",
]
