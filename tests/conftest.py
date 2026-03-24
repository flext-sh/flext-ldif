"""Test configuration and fixtures for flext-ldif tests.

Tests LDIF processing operations: parsing, writing, migration, validation.
Uses factories for data generation, helpers for assertions, and constants for configuration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from enum import StrEnum, unique
from pathlib import Path
from typing import Annotated, ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict, Field

from flext_ldif import FlextLdif, FlextLdifParser, FlextLdifWriter


def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: marks tests as unit tests")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "ldif: marks tests as LDIF-specific tests")
    config.addinivalue_line("markers", "docker: marks tests that require Docker")
    config.addinivalue_line("markers", "slow: marks tests as slow tests")
    config.addinivalue_line("markers", "real: marks tests using real functionality")


@pytest.fixture(scope="session")
def flext_ldif() -> FlextLdif:
    """Provide FlextLdif instance for tests."""
    return FlextLdif.get_instance()


@pytest.fixture
def temp_file(temp_dir: Path) -> Path:
    """Provide temporary LDIF file for tests.

    Uses the consolidated temp_dir fixture from flext-core.
    """
    return temp_dir / "test_file.ldif"


@pytest.fixture
def sample_ldif_entries() -> str:
    """Sample LDIF entries for testing."""
    return "dn: cn=John Doe,ou=people,dc=example,dc=com\nobjectClass: inetOrgPerson\ncn: John Doe\nsn: Doe\nmail: john.doe@example.com\n\ndn: cn=Jane Smith,ou=people,dc=example,dc=com\nobjectClass: inetOrgPerson\ncn: Jane Smith\nsn: Smith\nmail: jane.smith@example.com\n\ndn: ou=groups,dc=example,dc=com\nobjectClass: organizationalUnit\nou: groups\ndescription: Groups organizational unit\n"


@pytest.fixture
def real_ldif_user_entry() -> str:
    """Real LDIF entry for a user with complete attributes."""
    return "dn: cn=John Doe,ou=people,dc=example,dc=com\nobjectClass: top\nobjectClass: person\nobjectClass: inetOrgPerson\nobjectClass: organizationalPerson\ncn: John Doe\nsn: Doe\ngivenName: John\nmail: john.doe@example.com\nuid: jdoe\ntelephoneNumber: +1-555-1234\nstreet: 123 Main St\nl: New York\nst: NY\npostalCode: 10001\nc: US\ndescription: Software Engineer\nemployeeNumber: 12345\n"


@pytest.fixture
def real_ldif_group_entry() -> str:
    """Real LDIF entry for a group with complete attributes."""
    return "dn: cn=developers,ou=groups,dc=example,dc=com\nobjectClass: top\nobjectClass: groupOfNames\nobjectClass: groupOfUniqueNames\ncn: developers\ndescription: Development team group\nmember: cn=John Doe,ou=people,dc=example,dc=com\nmember: cn=Jane Smith,ou=people,dc=example,dc=com\nuniqueMember: cn=John Doe,ou=people,dc=example,dc=com\nuniqueMember: cn=Jane Smith,ou=people,dc=example,dc=com\n"


@pytest.fixture
def real_ldif_multiple_entries() -> str:
    """Real LDIF with multiple entries separated by blank lines."""
    return "dn: dc=example,dc=com\nobjectClass: top\nobjectClass: domain\ndc: example\n\ndn: ou=people,dc=example,dc=com\nobjectClass: top\nobjectClass: organizationalUnit\nou: people\n\ndn: cn=John Doe,ou=people,dc=example,dc=com\nobjectClass: top\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: John Doe\nsn: Doe\nmail: john.doe@example.com\n\ndn: cn=Jane Smith,ou=people,dc=example,dc=com\nobjectClass: top\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: Jane Smith\nsn: Smith\nmail: jane.smith@example.com\n"


@pytest.fixture
def ldif_parser() -> FlextLdifParser:
    """Provide LDIF parser for tests."""
    return FlextLdifParser()


@pytest.fixture
def ldif_writer() -> FlextLdifWriter:
    """Provide LDIF writer for tests."""
    return FlextLdifWriter()


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

    _instances: ClassVar[
        dict[
            str,
            FlextLdifFixtures.OID
            | FlextLdifFixtures.OUD
            | FlextLdifFixtures.OpenLDAP
            | FlextLdifFixtures.Loader,
        ]
    ] = {}

    @classmethod
    def get_oid(cls) -> FlextLdifFixtures.OID:
        """Get singleton OID fixture loader."""
        if "oid" not in cls._instances:
            cls._instances["oid"] = cls.OID()
        instance = cls._instances["oid"]
        assert isinstance(instance, cls.OID)
        return instance

    @classmethod
    def get_oud(cls) -> FlextLdifFixtures.OUD:
        """Get singleton OUD fixture loader."""
        if "oud" not in cls._instances:
            cls._instances["oud"] = cls.OUD()
        instance = cls._instances["oud"]
        assert isinstance(instance, cls.OUD)
        return instance

    @classmethod
    def get_openldap(cls) -> FlextLdifFixtures.OpenLDAP:
        """Get singleton OpenLDAP fixture loader."""
        if "openldap" not in cls._instances:
            cls._instances["openldap"] = cls.OpenLDAP()
        instance = cls._instances["openldap"]
        assert isinstance(instance, cls.OpenLDAP)
        return instance

    @classmethod
    def get_loader(cls) -> FlextLdifFixtures.Loader:
        """Get singleton generic fixture loader."""
        if "loader" not in cls._instances:
            cls._instances["loader"] = cls.Loader()
        instance = cls._instances["loader"]
        assert isinstance(instance, cls.Loader)
        return instance

    @unique
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

    @unique
    class FixtureType(StrEnum):
        """Types of fixtures available for each server."""

        SCHEMA = "schema"
        ACL = "acl"
        ENTRIES = "entries"
        INTEGRATION = "integration"

    class Metadata(BaseModel):
        """Metadata about a loaded fixture."""

        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

        server_type: Annotated[
            FlextLdifFixtures.ServerType,
            Field(
                description="LDAP server type for the fixture",
            ),
        ]
        fixture_type: Annotated[
            FlextLdifFixtures.FixtureType,
            Field(
                description="Fixture category identifier",
            ),
        ]
        file_path: Annotated[Path, Field(description="Fixture file path")]
        line_count: Annotated[
            int, Field(description="Number of lines in the fixture file"),
        ]
        entry_count: Annotated[
            int, Field(description="Number of LDIF entries in the fixture"),
        ]
        size_bytes: Annotated[int, Field(description="Fixture file size in bytes")]

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

        _content_cache: ClassVar[
            MutableMapping[
                tuple[FlextLdifFixtures.ServerType, FlextLdifFixtures.FixtureType],
                str,
            ]
        ] = {}
        _metadata_cache: ClassVar[MutableMapping[Path, FlextLdifFixtures.Metadata]] = {}

        def __init__(self, fixtures_root: Path | None = None) -> None:
            """Initialize fixture loader.

            Args:
                fixtures_root: Root directory for fixtures. Defaults to tests/fixtures/

            """
            if fixtures_root is None:
                conftest_dir = Path(__file__).parent
                fixtures_root = conftest_dir / "fixtures"
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
                msg = f"Fixture file not found: {file_path}\nExpected: {server_type.value}/{filename}"
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
        ) -> Mapping[FlextLdifFixtures.FixtureType, str]:
            """Load all fixtures for a server type.

            Args:
                server_type: Server type to load fixtures for

            Returns:
                Dict mapping fixture types to their content strings

            """
            fixtures: MutableMapping[FlextLdifFixtures.FixtureType, str] = {}
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
                    continue
            return fixtures

        def get_available_servers(self) -> Sequence[FlextLdifFixtures.ServerType]:
            """Get list of servers that have fixtures available.

            Returns:
                list: List of server types with fixture directories

            """
            available: Sequence[FlextLdifFixtures.ServerType] = []
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
        ) -> Sequence[FlextLdifFixtures.FixtureType]:
            """Get list of available fixture types for a server.

            Args:
                server_type: LDAP server type

            Returns:
                list: List of available fixture types for this server

            """
            available: Sequence[FlextLdifFixtures.FixtureType] = []
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
            if file_path in self._metadata_cache:
                return self._metadata_cache[file_path]
            content = self.load(server_type, fixture_type)
            lines = content.splitlines()
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

        def all(self) -> Mapping[FlextLdifFixtures.FixtureType, str]:
            """Load all OID fixtures.

            Returns:
                t.ContainerMapping: All available OID fixtures

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
            self._server_type = FlextLdifFixtures.ServerType.OUD

        def schema(self) -> str:
            """Load OUD schema fixtures."""
            return self._loader.load(
                self._server_type,
                FlextLdifFixtures.FixtureType.SCHEMA,
            )

        def acl(self) -> str:
            """Load OUD ACL fixtures."""
            return self._loader.load(
                self._server_type,
                FlextLdifFixtures.FixtureType.ACL,
            )

        def entries(self) -> str:
            """Load OUD entry fixtures."""
            return self._loader.load(
                self._server_type,
                FlextLdifFixtures.FixtureType.ENTRIES,
            )

        def integration(self) -> str:
            """Load OUD integration fixtures."""
            return self._loader.load(
                self._server_type,
                FlextLdifFixtures.FixtureType.INTEGRATION,
            )

        def all(self) -> Mapping[FlextLdifFixtures.FixtureType, str]:
            """Load all OUD fixtures."""
            return self._loader.load_all(self._server_type)

    class RFC:
        """RFC fixture loader.

        Provides direct access to RFC-compliant fixtures.
        """

        def __init__(self, fixtures_root: Path | None = None) -> None:
            """Initialize RFC fixture loader."""
            self._loader = FlextLdifFixtures.Loader(fixtures_root)
            self._server_type = FlextLdifFixtures.ServerType.RFC

        def schema(self) -> str:
            """Load RFC schema fixtures."""
            return self._loader.load(
                self._server_type,
                FlextLdifFixtures.FixtureType.SCHEMA,
            )

        def acl(self) -> str:
            """Load RFC ACL fixtures."""
            return self._loader.load(
                self._server_type,
                FlextLdifFixtures.FixtureType.ACL,
            )

        def entries(self) -> str:
            """Load RFC entry fixtures."""
            return self._loader.load(
                self._server_type,
                FlextLdifFixtures.FixtureType.ENTRIES,
            )

        def integration(self) -> str:
            """Load RFC integration fixtures."""
            return self._loader.load(
                self._server_type,
                FlextLdifFixtures.FixtureType.INTEGRATION,
            )

        def all(self) -> Mapping[FlextLdifFixtures.FixtureType, str]:
            """Load all RFC fixtures."""
            return self._loader.load_all(self._server_type)

    class OpenLDAP:
        """OpenLDAP fixture loader.

        Provides direct access to OpenLDAP-specific fixtures.
        """

        def __init__(self, fixtures_root: Path | None = None) -> None:
            """Initialize OpenLDAP fixture loader."""
            self._loader = FlextLdifFixtures.Loader(fixtures_root)
            self._server_type = FlextLdifFixtures.ServerType.OPENLDAP

        def schema(self) -> str:
            """Load OpenLDAP schema fixtures."""
            return self._loader.load(
                self._server_type,
                FlextLdifFixtures.FixtureType.SCHEMA,
            )

        def acl(self) -> str:
            """Load OpenLDAP ACL fixtures."""
            return self._loader.load(
                self._server_type,
                FlextLdifFixtures.FixtureType.ACL,
            )

        def entries(self) -> str:
            """Load OpenLDAP entry fixtures."""
            return self._loader.load(
                self._server_type,
                FlextLdifFixtures.FixtureType.ENTRIES,
            )

        def integration(self) -> str:
            """Load OpenLDAP integration fixtures."""
            return self._loader.load(
                self._server_type,
                FlextLdifFixtures.FixtureType.INTEGRATION,
            )

        def all(self) -> Mapping[FlextLdifFixtures.FixtureType, str]:
            """Load all OpenLDAP fixtures."""
            return self._loader.load_all(self._server_type)


FIXTURES_DIR: Final[Path] = Path(__file__).parent / "fixtures"
OID_FIXTURES_DIR: Final[Path] = FIXTURES_DIR / "oid"
