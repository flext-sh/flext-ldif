"""Shared unit-oriented pytest fixtures for flext-ldif tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_ldif import ldif
from flext_ldif.services.conversion import FlextLdifConversion
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.writer import FlextLdifWriter
from tests.constants import c
from tests.utilities import u

if TYPE_CHECKING:
    from pathlib import Path

    from tests.models import m
    from tests.protocols import p
    from tests.typings import t


@pytest.fixture
def api() -> p.Ldif.LdifClient:
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
    fixture_content: str = u.Tests.load(c.Tests.OID, c.Tests.SCHEMA)
    return fixture_content


@pytest.fixture
def oid_acl_fixture() -> str:
    """Load OID ACL fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OID, c.Tests.ACL)
    return fixture_content


@pytest.fixture
def oid_entries_fixture() -> str:
    """Load OID entries fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OID, c.Tests.ENTRIES)
    return fixture_content


@pytest.fixture
def oid_integration_fixture() -> str:
    """Load OID integration fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OID, c.Tests.INTEGRATION)
    return fixture_content


@pytest.fixture
def oid_entries(
    api: p.Ldif.LdifClient,
    oid_entries_fixture: str,
) -> t.SequenceOf[m.Ldif.Entry]:
    """Parse OID entries fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.Tests.assert_success(
        api.parse_ldif(oid_entries_fixture),
        error_msg="OID entries parsing failed",
    )
    entries: t.SequenceOf[m.Ldif.Entry] = parse_response.entries
    return entries


@pytest.fixture
def oud_schema_fixture() -> str:
    """Load OUD schema fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.SCHEMA)
    return fixture_content


@pytest.fixture
def oud_acl_fixture() -> str:
    """Load OUD ACL fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.ACL)
    return fixture_content


@pytest.fixture
def oud_entries_fixture() -> str:
    """Load OUD entries fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.ENTRIES)
    return fixture_content


@pytest.fixture
def oud_integration_fixture() -> str:
    """Load OUD integration fixture data."""
    fixture_content: str = u.Tests.load(c.Tests.OUD, c.Tests.INTEGRATION)
    return fixture_content


@pytest.fixture
def oud_entries(
    api: p.Ldif.LdifClient,
    oud_entries_fixture: str,
) -> t.SequenceOf[m.Ldif.Entry]:
    """Parse OUD entries fixture into Entry models."""
    parse_response: m.Ldif.ParseResponse = u.Tests.assert_success(
        api.parse_ldif(oud_entries_fixture),
        error_msg="OUD entries parsing failed",
    )
    entries: t.SequenceOf[m.Ldif.Entry] = parse_response.entries
    return entries


@pytest.fixture
def fixtures_dir() -> Path:
    """Get path to fixtures directory."""
    fixtures_root: Path = c.Tests.FIXTURES_DIR
    return fixtures_root


@pytest.fixture
def conversion_matrix() -> FlextLdifConversion:
    """Create FlextLdifConversion instance for conversion tests."""
    return FlextLdifConversion()


@pytest.fixture
def server() -> p.Ldif.ServerRegistry:
    """Get FlextLdifServer instance for server management."""
    server_registry: p.Ldif.ServerRegistry = FlextLdifServer.fetch_global_instance()
    return server_registry


@pytest.fixture
def oid_server(server: p.Ldif.ServerRegistry) -> p.Ldif.ServerServer:
    """Get OID server via FlextLdifServer API."""
    return u.Tests.assert_success(
        server.server("oid"),
        error_msg="OID server must be registered",
    )


@pytest.fixture
def oud_server(server: p.Ldif.ServerRegistry) -> p.Ldif.ServerServer:
    """Get OUD server via FlextLdifServer API."""
    return u.Tests.assert_success(
        server.resolve_base_server("oud"),
        error_msg="OUD server must be registered",
    )


@pytest.fixture
def oid_schema_server(oid_server: p.Ldif.ServerServer) -> p.Ldif.SchemaServer:
    """Create OID schema server instance for conversion tests."""
    return oid_server.schema_server


@pytest.fixture
def oud_schema_server(oud_server: p.Ldif.ServerServer) -> p.Ldif.SchemaServer:
    """Create OUD schema server instance for conversion tests."""
    return oud_server.schema_server


@pytest.fixture
def oid_acl_server(oid_server: p.Ldif.ServerServer) -> p.Ldif.AclServer:
    """Create OID ACL server instance for conversion tests."""
    return oid_server.acl_server


@pytest.fixture
def oud_acl_server(oud_server: p.Ldif.ServerServer) -> p.Ldif.AclServer:
    """Create OUD ACL server instance for conversion tests."""
    return oud_server.acl_server


@pytest.fixture
def migration_dirs(tmp_path: Path) -> t.Pair[Path, Path]:
    """Provide canonical (input_dir, output_dir) pair for migration tests.

    Both directories are created under ``tmp_path`` so tests get clean
    isolation per pytest invocation.
    """
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    output_dir.mkdir()
    return input_dir, output_dir


@pytest.fixture
def migration_pipeline_factory(
    migration_dirs: t.Pair[Path, Path],
) -> p.Tests.MigrationPipelineFactory:
    """Return a factory that builds ``FlextLdifMigrationPipeline`` instances.

    Defaults to the canonical ``RFC -> RFC`` flow with the migration_dirs
    fixture. Callers override any kwarg (``source_server_type``,
    ``target_server_type``, ``input_dir``, ``output_dir``) to vary the case.
    """
    default_input, default_output = migration_dirs

    def _build(
        *,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        source_server_type: c.Ldif.ServerTypes | str | None = None,
        target_server_type: c.Ldif.ServerTypes | str | None = None,
    ) -> FlextLdifMigrationPipeline:
        return FlextLdifMigrationPipeline(
            input_dir=input_dir if input_dir is not None else default_input,
            output_dir=output_dir if output_dir is not None else default_output,
            source_server_type=source_server_type or c.Tests.RFC,
            target_server_type=target_server_type or c.Tests.RFC,
        )

    return _build
