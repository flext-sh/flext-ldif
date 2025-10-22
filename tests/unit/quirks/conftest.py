"""Shared pytest fixtures for LDAP quirks testing.

Provides session-level fixture loading and common test utilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from tests.fixtures.loader import FlextLdifFixtures
from tests.fixtures.validator import FixtureCoverageReport, FixtureValidator


@pytest.fixture(scope="session")
def fixture_loader() -> FlextLdifFixtures.Loader:
    """Session-scoped fixture loader for all quirk tests.

    Returns:
        FlextLdifFixtures.Loader instance

    """
    return FlextLdifFixtures.Loader()


@pytest.fixture(scope="session")
def all_server_fixtures(
    fixture_loader: FlextLdifFixtures.Loader,
) -> dict[str, dict[str, str]]:
    """Load ALL fixtures for 4 primary servers at session start.

    Returns:
        Dict mapping server type to fixture content dicts

    """
    fixtures: dict[str, dict[str, str]] = {}

    servers = [
        FlextLdifFixtures.ServerType.RFC,
        FlextLdifFixtures.ServerType.OID,
        FlextLdifFixtures.ServerType.OUD,
        FlextLdifFixtures.ServerType.OPENLDAP,
    ]

    for server in servers:
        try:
            fixtures[server.value] = fixture_loader.load_all(server)
        except FileNotFoundError:
            # Server fixtures may not all be available
            fixtures[server.value] = {}

    return fixtures


@pytest.fixture(scope="session")
def fixture_coverage_report(
    all_server_fixtures: dict[str, dict[str, str]],
) -> dict[str, object]:
    """Generate coverage report for all fixtures.

    Returns:
        Coverage report statistics

    """
    return FixtureCoverageReport.generate_summary(all_server_fixtures)


@pytest.fixture
def fixture_validator() -> FixtureValidator:
    """Validator instance for fixture operations.

    Returns:
        FixtureValidator instance

    """
    return FixtureValidator()


@pytest.fixture
def rfc_fixtures(all_server_fixtures: dict[str, dict[str, str]]) -> dict[str, str]:
    """RFC fixture content.

    Returns:
        Dict with 'schema', 'entries', 'acl', 'integration' keys

    """
    return all_server_fixtures.get("rfc", {})


@pytest.fixture
def oid_fixtures(all_server_fixtures: dict[str, dict[str, str]]) -> dict[str, str]:
    """OID fixture content.

    Returns:
        Dict with 'schema', 'entries', 'acl', 'integration' keys

    """
    return all_server_fixtures.get("oid", {})


@pytest.fixture
def oud_fixtures(all_server_fixtures: dict[str, dict[str, str]]) -> dict[str, str]:
    """OUD fixture content.

    Returns:
        Dict with 'schema', 'entries', 'acl', 'integration' keys

    """
    return all_server_fixtures.get("oud", {})


@pytest.fixture
def openldap_fixtures(all_server_fixtures: dict[str, dict[str, str]]) -> dict[str, str]:
    """OpenLDAP fixture content.

    Returns:
        Dict with 'schema', 'entries', 'acl', 'integration' keys

    """
    return all_server_fixtures.get("openldap", {})


__all__ = [
    "all_server_fixtures",
    "fixture_coverage_report",
    "fixture_loader",
    "fixture_validator",
    "oid_fixtures",
    "openldap_fixtures",
    "oud_fixtures",
    "rfc_fixtures",
]
