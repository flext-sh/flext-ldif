"""Fixture loader for LDAP server quirks testing.

Provides generic fixture loading infrastructure for multiple LDAP server types
following FLEXT architectural patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from dataclasses import dataclass

# Python 3.13+
from enum import StrEnum
from pathlib import Path
from typing import ClassVar, Final, cast

from tests.fixtures.typing import GenericFieldsDict


class FlextLdifFixtures:
    """FLEXT LDIF fixture loading infrastructure.

    Provides standardized access to test fixtures for different LDAP servers.
    Follows FLEXT architectural patterns with nested classes for organization.

    Usage:
        # Generic loading
        loader = FlextLdifFixtures.Loader()
        oid_schema = loader.load(FlextLdifFixtures.ServerType.OID, FlextLdifFixtures.FixtureType.SCHEMA)

        # Server-specific loading (singleton pattern for performance)
        oid = FlextLdifFixtures.get_oid()  # Cached singleton
        schema = oid.schema()
        acl = oid.acl()

        # Metadata inspection
        metadata = loader.get_metadata(FlextLdifFixtures.ServerType.OID, FlextLdifFixtures.FixtureType.SCHEMA)
    """

    # Singleton instances for server-specific loaders
    _instances: ClassVar[GenericFieldsDict] = {}

    @classmethod
    def get_oid(cls) -> FlextLdifFixtures.OID:
        """Get singleton OID fixture loader."""
        if "oid" not in cls._instances:
            cls._instances["oid"] = cls.OID()
        return cast("FlextLdifFixtures.OID", cls._instances["oid"])

    @classmethod
    def get_oud(cls) -> FlextLdifFixtures.OUD:
        """Get singleton OUD fixture loader."""
        if "oud" not in cls._instances:
            cls._instances["oud"] = cls.OUD()
        return cast("FlextLdifFixtures.OUD", cls._instances["oud"])

    @classmethod
    def get_openldap(cls) -> FlextLdifFixtures.OpenLDAP:
        """Get singleton OpenLDAP fixture loader."""
        if "openldap" not in cls._instances:
            cls._instances["openldap"] = cls.OpenLDAP()
        return cast("FlextLdifFixtures.OpenLDAP", cls._instances["openldap"])

    @classmethod
    def get_loader(cls) -> FlextLdifFixtures.Loader:
        """Get singleton generic fixture loader."""
        if "loader" not in cls._instances:
            cls._instances["loader"] = cls.Loader()
        return cast("FlextLdifFixtures.Loader", cls._instances["loader"])

    class ServerType(StrEnum):
        """Supported LDAP server types with quirks."""

        RFC = "rfc"
        OID = "oid"
        OUD = "oud"
        OPENLDAP = "openldap"
        OPENLDAP1 = "openldap1"
        DS389 = "ds389"
        APACHE = "apache"
        NOVELL = "novell"
        TIVOLI = "tivoli"
        AD = "ad"

    class FixtureType(StrEnum):
        """Types of fixtures available for each server."""

        SCHEMA = "schema"
        ACL = "acl"
        ENTRIES = "entries"
        INTEGRATION = "integration"

    @dataclass(frozen=True)
    class Metadata:
        """Metadata about a loaded fixture."""

        server_type: FlextLdifFixtures.ServerType
        fixture_type: FlextLdifFixtures.FixtureType
        file_path: Path
        line_count: int
        entry_count: int
        size_bytes: int

    class Loader:
        """Generic fixture loader for all LDAP server types.

        Provides standardized access to test fixtures with consistent naming.
        Each server has a directory structure:
            tests/fixtures/{server_type}/
                {server_type}_schema_fixtures.ldif
                {server_type}_acl_fixtures.ldif
                {server_type}_entries_fixtures.ldif
                {server_type}_integration_fixtures.ldif
        """

        # Class-level caches for performance optimization
        _content_cache: ClassVar[
            dict[
                tuple[FlextLdifFixtures.ServerType, FlextLdifFixtures.FixtureType],
                str,
            ]
        ] = {}
        _metadata_cache: ClassVar[dict[Path, FlextLdifFixtures.Metadata]] = {}

        def __init__(self, fixtures_root: Path | None = None) -> None:
            """Initialize fixture loader.

            Args:
                fixtures_root: Root directory for fixtures. Defaults to tests/fixtures/

            """
            if fixtures_root is None:
                fixtures_root = Path(__file__).parent
            self.fixtures_root: Final[Path] = fixtures_root

        def _get_fixture_path(
            self,
            server_type: FlextLdifFixtures.ServerType,
            fixture_type: FlextLdifFixtures.FixtureType,
        ) -> Path:
            """Get path to a specific fixture file.

            Args:
                server_type: LDAP server type
                fixture_type: Type of fixture to load

            Returns:
                Path: Path to fixture file

            Raises:
                FileNotFoundError: If fixture file doesn't exist

            """
            server_dir = self.fixtures_root / server_type.value
            filename = f"{server_type.value}_{fixture_type.value}_fixtures.ldif"
            file_path = server_dir / filename

            if not file_path.exists():
                msg = (
                    f"Fixture file not found: {file_path}\n"
                    f"Expected: {server_type.value}/{filename}"
                )
                raise FileNotFoundError(msg)

            return file_path

        def load(
            self,
            server_type: FlextLdifFixtures.ServerType,
            fixture_type: FlextLdifFixtures.FixtureType,
        ) -> str:
            """Load a specific fixture file.

            Args:
                server_type: LDAP server type
                fixture_type: Type of fixture to load

            Returns:
                str: LDIF content from fixture file

            Raises:
                FileNotFoundError: If fixture file doesn't exist

            """
            cache_key = (server_type, fixture_type)
            if cache_key not in self._content_cache:
                file_path = self._get_fixture_path(server_type, fixture_type)
                self._content_cache[cache_key] = file_path.read_text(encoding="utf-8")
            return self._content_cache[cache_key]

        def load_all(
            self,
            server_type: FlextLdifFixtures.ServerType,
        ) -> dict[FlextLdifFixtures.FixtureType, str]:
            """Load all fixtures for a server type.

            Args:
                server_type: Server type to load fixtures for

            Returns:
                Dict mapping fixture types to their content strings

            """
            fixtures: dict[FlextLdifFixtures.FixtureType, str] = {}

            fixture_types = [
                FlextLdifFixtures.FixtureType.SCHEMA,
                FlextLdifFixtures.FixtureType.ACL,
                FlextLdifFixtures.FixtureType.ENTRIES,
                FlextLdifFixtures.FixtureType.INTEGRATION,
            ]
            for fixture_type in fixture_types:
                try:
                    fixtures[fixture_type] = self.load(server_type, fixture_type)
                except FileNotFoundError:
                    # Skip fixtures that don't exist for this server
                    continue

            return fixtures

        def get_available_servers(self) -> list[FlextLdifFixtures.ServerType]:
            """Get list of servers that have fixtures available.

            Returns:
                list: List of server types with fixture directories

            """
            available: list[FlextLdifFixtures.ServerType] = []

            server_types = [
                FlextLdifFixtures.ServerType.OID,
                FlextLdifFixtures.ServerType.OUD,
                FlextLdifFixtures.ServerType.OPENLDAP,
                FlextLdifFixtures.ServerType.OPENLDAP1,
                FlextLdifFixtures.ServerType.DS389,
                FlextLdifFixtures.ServerType.APACHE,
                FlextLdifFixtures.ServerType.NOVELL,
                FlextLdifFixtures.ServerType.TIVOLI,
                FlextLdifFixtures.ServerType.AD,
            ]
            for server_type in server_types:
                server_dir = self.fixtures_root / server_type.value
                if server_dir.exists() and server_dir.is_dir():
                    available.append(server_type)

            return available

        def get_available_fixtures(
            self,
            server_type: FlextLdifFixtures.ServerType,
        ) -> list[FlextLdifFixtures.FixtureType]:
            """Get list of available fixture types for a server.

            Args:
                server_type: LDAP server type

            Returns:
                list: List of available fixture types for this server

            """
            available: list[FlextLdifFixtures.FixtureType] = []

            for fixture_type in FlextLdifFixtures.FixtureType.__members__.values():
                try:
                    self._get_fixture_path(server_type, fixture_type)
                    available.append(fixture_type)
                except FileNotFoundError:
                    continue

            return available

        def get_metadata(
            self,
            server_type: FlextLdifFixtures.ServerType,
            fixture_type: FlextLdifFixtures.FixtureType,
        ) -> FlextLdifFixtures.Metadata:
            """Get metadata about a fixture file.

            Args:
                server_type: LDAP server type
                fixture_type: Type of fixture

            Returns:
                FlextLdifFixtures.Metadata: Metadata about the fixture file

            Raises:
                FileNotFoundError: If fixture file doesn't exist

            """
            file_path = self._get_fixture_path(server_type, fixture_type)

            # Use cache if available
            if file_path in self._metadata_cache:
                return self._metadata_cache[file_path]

            # Use content cache to avoid double read
            content = self.load(server_type, fixture_type)
            lines = content.splitlines()

            # Count entries (lines starting with "dn:")
            entry_count = sum(1 for line in lines if line.strip().startswith("dn:"))

            metadata = FlextLdifFixtures.Metadata(
                server_type=server_type,
                fixture_type=fixture_type,
                file_path=file_path,
                line_count=len(lines),
                entry_count=entry_count,
                size_bytes=file_path.stat().st_size,
            )

            self._metadata_cache[file_path] = metadata
            return metadata

        def fixture_exists(
            self,
            server_type: FlextLdifFixtures.ServerType,
            fixture_type: FlextLdifFixtures.FixtureType,
        ) -> bool:
            """Check if a fixture file exists.

            Args:
                server_type: LDAP server type
                fixture_type: Type of fixture

            Returns:
                bool: True if fixture exists, False otherwise

            """
            try:
                self._get_fixture_path(server_type, fixture_type)
                return True
            except FileNotFoundError:
                return False

    class OID:
        """Oracle Internet Directory fixture loader.

        Provides direct access to OID-specific fixtures without enum parameters.

        Usage:
            oid = FlextLdifFixtures.OID()
            schema = oid.schema()
            integration = oid.integration()
        """

        def __init__(self, fixtures_root: Path | None = None) -> None:
            """Initialize OID fixture loader.

            Args:
                fixtures_root: Root directory for fixtures. Defaults to tests/fixtures/

            """
            self._loader = FlextLdifFixtures.Loader(fixtures_root)

        def schema(self) -> str:
            """Load OID schema fixtures.

            Returns:
                str: LDIF content with OID schema definitions

            """
            return self._loader.load(
                FlextLdifFixtures.ServerType.OID,
                FlextLdifFixtures.FixtureType.SCHEMA,
            )

        def acl(self) -> str:
            """Load OID ACL fixtures.

            Returns:
                str: LDIF content with OID ACL definitions

            """
            return self._loader.load(
                FlextLdifFixtures.ServerType.OID,
                FlextLdifFixtures.FixtureType.ACL,
            )

        def entries(self) -> str:
            """Load OID entry fixtures.

            Returns:
                str: LDIF content with OID directory entries

            """
            return self._loader.load(
                FlextLdifFixtures.ServerType.OID,
                FlextLdifFixtures.FixtureType.ENTRIES,
            )

        def integration(self) -> str:
            """Load OID integration fixtures.

            Returns:
                str: LDIF content with complete OID directory structure and real quirks

            """
            return self._loader.load(
                FlextLdifFixtures.ServerType.OID,
                FlextLdifFixtures.FixtureType.INTEGRATION,
            )

        def all(self) -> dict[FlextLdifFixtures.FixtureType, str]:
            """Load all OID fixtures.

            Returns:
                dict[str, object]: All available OID fixtures

            """
            return self._loader.load_all(FlextLdifFixtures.ServerType.OID)

        def metadata(
            self,
            fixture_type: FlextLdifFixtures.FixtureType,
        ) -> FlextLdifFixtures.Metadata:
            """Get metadata about an OID fixture.

            Args:
                fixture_type: Type of fixture

            Returns:
                FlextLdifFixtures.Metadata: Metadata about the fixture file

            """
            return self._loader.get_metadata(
                FlextLdifFixtures.ServerType.OID,
                fixture_type,
            )

    class OUD:
        """Oracle Unified Directory fixture loader.

        Provides direct access to OUD-specific fixtures.
        """

        def __init__(self, fixtures_root: Path | None = None) -> None:
            """Initialize OUD fixture loader."""
            self._loader = FlextLdifFixtures.Loader(fixtures_root)

        def schema(self) -> str:
            """Load OUD schema fixtures."""
            return self._loader.load(
                FlextLdifFixtures.ServerType.OUD,
                FlextLdifFixtures.FixtureType.SCHEMA,
            )

        def acl(self) -> str:
            """Load OUD ACL fixtures."""
            return self._loader.load(
                FlextLdifFixtures.ServerType.OUD,
                FlextLdifFixtures.FixtureType.ACL,
            )

        def entries(self) -> str:
            """Load OUD entry fixtures."""
            return self._loader.load(
                FlextLdifFixtures.ServerType.OUD,
                FlextLdifFixtures.FixtureType.ENTRIES,
            )

        def integration(self) -> str:
            """Load OUD integration fixtures."""
            return self._loader.load(
                FlextLdifFixtures.ServerType.OUD,
                FlextLdifFixtures.FixtureType.INTEGRATION,
            )

        def all(self) -> dict[FlextLdifFixtures.FixtureType, str]:
            """Load all OUD fixtures."""
            return self._loader.load_all(FlextLdifFixtures.ServerType.OUD)

    class RFC:
        """RFC fixture loader.

        Provides direct access to RFC-compliant fixtures.
        """

        def __init__(self, fixtures_root: Path | None = None) -> None:
            """Initialize RFC fixture loader."""
            self._loader = FlextLdifFixtures.Loader(fixtures_root)

        def schema(self) -> str:
            """Load RFC schema fixtures."""
            return self._loader.load(
                FlextLdifFixtures.ServerType.RFC,
                FlextLdifFixtures.FixtureType.SCHEMA,
            )

        def acl(self) -> str:
            """Load RFC ACL fixtures."""
            return self._loader.load(
                FlextLdifFixtures.ServerType.RFC,
                FlextLdifFixtures.FixtureType.ACL,
            )

        def entries(self) -> str:
            """Load RFC entry fixtures."""
            return self._loader.load(
                FlextLdifFixtures.ServerType.RFC,
                FlextLdifFixtures.FixtureType.ENTRIES,
            )

        def integration(self) -> str:
            """Load RFC integration fixtures."""
            return self._loader.load(
                FlextLdifFixtures.ServerType.RFC,
                FlextLdifFixtures.FixtureType.INTEGRATION,
            )

        def all(self) -> dict[FlextLdifFixtures.FixtureType, str]:
            """Load all RFC fixtures."""
            return self._loader.load_all(FlextLdifFixtures.ServerType.RFC)

    class OpenLDAP:
        """OpenLDAP fixture loader.

        Provides direct access to OpenLDAP-specific fixtures.
        """

        def __init__(self, fixtures_root: Path | None = None) -> None:
            """Initialize OpenLDAP fixture loader."""
            self._loader = FlextLdifFixtures.Loader(fixtures_root)

        def schema(self) -> str:
            """Load OpenLDAP schema fixtures."""
            return self._loader.load(
                FlextLdifFixtures.ServerType.OPENLDAP,
                FlextLdifFixtures.FixtureType.SCHEMA,
            )

        def acl(self) -> str:
            """Load OpenLDAP ACL fixtures."""
            return self._loader.load(
                FlextLdifFixtures.ServerType.OPENLDAP,
                FlextLdifFixtures.FixtureType.ACL,
            )

        def entries(self) -> str:
            """Load OpenLDAP entry fixtures."""
            return self._loader.load(
                FlextLdifFixtures.ServerType.OPENLDAP,
                FlextLdifFixtures.FixtureType.ENTRIES,
            )

        def integration(self) -> str:
            """Load OpenLDAP integration fixtures."""
            return self._loader.load(
                FlextLdifFixtures.ServerType.OPENLDAP,
                FlextLdifFixtures.FixtureType.INTEGRATION,
            )

        def all(self) -> dict[FlextLdifFixtures.FixtureType, str]:
            """Load all OpenLDAP fixtures."""
            return self._loader.load_all(FlextLdifFixtures.ServerType.OPENLDAP)


__all__ = ["FlextLdifFixtures"]
