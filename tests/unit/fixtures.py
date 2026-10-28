"""Shared unit-oriented pytest fixtures for flext-ldif tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import Sequence
from typing import TYPE_CHECKING

import pytest

from flext_ldif import FlextLdif, services
from tests import c, ldif, m, p, u

if TYPE_CHECKING:
    from pathlib import Path


def _parse_fixture_entries(
    api: p.Ldif.LdifClient,
    fixture_content: str,
    error_msg: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse one fixture's LDIF text into Entry models.

    Args:
        api: LDIF client used to parse the fixture content.
        fixture_content: Raw LDIF text loaded from a fixture file.
        error_msg: Assertion message used when parsing fails.

    Returns:
        Parsed entries in fixture order.

    """
    parse_response: m.Ldif.ParseResponse = u.Tests.assert_success(
        api.parse_ldif(fixture_content),
        error_msg=error_msg,
    )
    entries: Sequence[m.Ldif.Entry] = parse_response.entries
    return entries


@pytest.fixture
def api() -> p.Ldif.LdifClient:
    """Provide the unified ``ldif()`` client entry point.

    Returns:
        A fresh LDIF client bound to the registered server flavors.

    """
    return ldif()


@pytest.fixture
def parser(server: p.Ldif.ServerRegistry) -> services.FlextLdifParser:
    """Provide a parser service instance.

    Returns:
        A fresh ``FlextLdifParser``.

    """
    return services.FlextLdifParser(registry=server.registry)


@pytest.fixture
def writer(api: p.Ldif.LdifClient) -> p.Ldif.LdifClient:
    """Provide writing operations from the public, registry-bound facade.

    Returns:
        The public client composed with its registered server dialects.

    """
    return api


@pytest.fixture
def oid_schema_fixture() -> str:
    """Load the OID schema fixture file.

    Returns:
        Raw OID schema LDIF text.

    """
    fixture_content: str = u.Tests.load(c.Tests.OID, c.Tests.SCHEMA)
    return fixture_content


@pytest.fixture
def oid_acl_fixture() -> str:
    """Load the OID ACL fixture file.

    Returns:
        Raw OID ACL LDIF text.

    """
    fixture_content: str = u.Tests.load(c.Tests.OID, c.Tests.ACL)
    return fixture_content


@pytest.fixture
def oid_entries_fixture() -> str:
    """Load the OID entries fixture file.

    Returns:
        Raw OID entry LDIF text.

    """
    fixture_content: str = u.Tests.load(c.Tests.OID, c.Tests.ENTRIES)
    return fixture_content


@pytest.fixture
def oid_integration_fixture() -> str:
    """Load the OID integration fixture file.

    Returns:
        Raw OID integration LDIF text combining schema, ACLs, and entries.

    """
    fixture_content: str = u.Tests.load(c.Tests.OID, c.Tests.INTEGRATION)
    return fixture_content


@pytest.fixture
def oid_entries(
    api: p.Ldif.LdifClient,
    oid_entries_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse the OID entries fixture into Entry models.

    Args:
        api: LDIF client used to parse the fixture content.
        oid_entries_fixture: Raw OID entry LDIF text.

    Returns:
        Parsed OID entries in fixture order.

    """
    return _parse_fixture_entries(
        api,
        oid_entries_fixture,
        "OID entries parsing failed",
    )


@pytest.fixture
def oud_schema_fixture() -> str:
    """Load the OUD schema fixture file.

    Returns:
        Raw OUD schema LDIF text.

    """
    fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.SCHEMA)
    return fixture_content


@pytest.fixture
def oud_acl_fixture() -> str:
    """Load the OUD ACL fixture file.

    Returns:
        Raw OUD ACL LDIF text.

    """
    fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.ACL)
    return fixture_content


@pytest.fixture
def oud_entries_fixture() -> str:
    """Load the OUD entries fixture file.

    Returns:
        Raw OUD entry LDIF text.

    """
    fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.ENTRIES)
    return fixture_content


@pytest.fixture
def oud_integration_fixture() -> str:
    """Load the OUD integration fixture file.

    Returns:
        Raw OUD integration LDIF text combining schema, ACLs, and entries.

    """
    fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.INTEGRATION)
    return fixture_content


@pytest.fixture
def oud_entries(
    api: p.Ldif.LdifClient,
    oud_entries_fixture: str,
) -> Sequence[m.Ldif.Entry]:
    """Parse the OUD entries fixture into Entry models.

    Args:
        api: LDIF client used to parse the fixture content.
        oud_entries_fixture: Raw OUD entry LDIF text.

    Returns:
        Parsed OUD entries in fixture order.

    """
    return _parse_fixture_entries(
        api,
        oud_entries_fixture,
        "OUD entries parsing failed",
    )


@pytest.fixture
def fixtures_dir() -> Path:
    """Provide the canonical test fixtures directory.

    Returns:
        Path to the shared fixtures root.

    """
    fixtures_root: Path = c.Tests.FIXTURES_DIR
    return fixtures_root


@pytest.fixture
def conversion_matrix(server: p.Ldif.ServerRegistry) -> services.FlextLdifConversion:
    """Provide a conversion service for schema conversion tests.

    Returns:
        A fresh ``FlextLdifConversion`` instance.

    """
    return services.FlextLdifConversion(registry=server.registry)


@pytest.fixture
def server() -> p.Ldif.ServerRegistry:
    """Provide the global server registry.

    Returns:
        The process-wide ``FlextLdifServer`` registry instance.

    """
    server_registry: p.Ldif.ServerRegistry = services.FlextLdifServer(
        registry=FlextLdif().registry
    )
    return server_registry


@pytest.fixture
def oid_server(server: p.Ldif.ServerRegistry) -> p.Ldif.ServerServer:
    """Resolve the registered OID server.

    Args:
        server: Global server registry.

    Returns:
        The registered OID server instance.

    """
    server_instance: p.Ldif.ServerServer = u.Tests.assert_success(
        server.server("oid"),
        error_msg="OID server must be registered",
    )
    return server_instance


@pytest.fixture
def oud_server(server: p.Ldif.ServerRegistry) -> p.Ldif.ServerServer:
    """Resolve the registered OUD server.

    Args:
        server: Global server registry.

    Returns:
        The registered OUD server instance.

    """
    server_instance: p.Ldif.ServerServer = u.Tests.assert_success(
        server.resolve_base_server("oud"),
        error_msg="OUD server must be registered",
    )
    return server_instance


@pytest.fixture
def oid_schema_server(oid_server: p.Ldif.ServerServer) -> p.Ldif.SchemaServer:
    """Provide the OID server's schema facade.

    Args:
        oid_server: Registered OID server.

    Returns:
        The OID schema server facade.

    """
    return oid_server.schema_server


@pytest.fixture
def oud_schema_server(oud_server: p.Ldif.ServerServer) -> p.Ldif.SchemaServer:
    """Provide the OUD server's schema facade.

    Args:
        oud_server: Registered OUD server.

    Returns:
        The OUD schema server facade.

    """
    return oud_server.schema_server


@pytest.fixture
def oid_acl_server(oid_server: p.Ldif.ServerServer) -> p.Ldif.AclServer:
    """Provide the OID server's ACL facade.

    Args:
        oid_server: Registered OID server.

    Returns:
        The OID ACL server facade.

    """
    return oid_server.acl_server


@pytest.fixture
def oud_acl_server(oud_server: p.Ldif.ServerServer) -> p.Ldif.AclServer:
    """Provide the OUD server's ACL facade.

    Args:
        oud_server: Registered OUD server.

    Returns:
        The OUD ACL server facade.

    """
    return oud_server.acl_server


@pytest.fixture
def migration_dirs(tmp_path: Path) -> tuple[Path, Path]:
    """Provide canonical (input_dir, output_dir) pair for migration tests.

    Both directories are created under ``tmp_path`` so tests get clean
    isolation per pytest invocation.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        Tuple of the created input and output directories.

    """
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    output_dir.mkdir()
    return input_dir, output_dir


@pytest.fixture
def migration_pipeline(
    migration_dirs: tuple[Path, Path],
    server: p.Ldif.ServerRegistry,
) -> p.Ldif.MigrationPipeline:
    """Provide the real registry-bound pipeline with model-owned defaults.

    Returns:
        The migration pipeline bound to the supplied registry and directories.

    """
    input_dir, output_dir = migration_dirs
    return services.FlextLdifMigrationPipeline(
        registry=server.registry,
        input_dir=input_dir,
        output_dir=output_dir,
    )
