"""Unit tests for FlextLdifFixtures loader.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from tests.fixtures import FlextLdifFixtures


class TestFlextLdifFixturesLoader:
    """Test FlextLdifFixtures.Loader class."""

    def test_loader_initialization(self) -> None:
        """Test loader can be initialized."""
        loader = FlextLdifFixtures.Loader()
        assert loader is not None
        assert loader.fixtures_root.exists()

    def test_load_oid_schema(self) -> None:
        """Test loading OID schema fixtures."""
        loader = FlextLdifFixtures.Loader()
        schema = loader.load(
            FlextLdifFixtures.ServerType.OID, FlextLdifFixtures.FixtureType.SCHEMA
        )

        assert schema
        assert "attributetypes" in schema
        assert "2.16.840.1.113894" in schema
        assert "orclOIDSCExtHost" in schema

    def test_load_oid_acl(self) -> None:
        """Test loading OID ACL fixtures."""
        loader = FlextLdifFixtures.Loader()
        acl = loader.load(
            FlextLdifFixtures.ServerType.OID, FlextLdifFixtures.FixtureType.ACL
        )

        assert acl
        assert "orclaci" in acl
        assert "orclentrylevelaci" in acl

    def test_load_oid_entries(self) -> None:
        """Test loading OID entry fixtures."""
        loader = FlextLdifFixtures.Loader()
        entries = loader.load(
            FlextLdifFixtures.ServerType.OID, FlextLdifFixtures.FixtureType.ENTRIES
        )

        assert entries
        assert "objectclass:" in entries.lower()
        assert "dn:" in entries

    def test_load_oid_integration(self) -> None:
        """Test loading OID integration fixtures."""
        loader = FlextLdifFixtures.Loader()
        integration = loader.load(
            FlextLdifFixtures.ServerType.OID,
            FlextLdifFixtures.FixtureType.INTEGRATION,
        )

        assert integration
        assert "REAL OID QUIRKS" in integration
        assert "groupofuniquenames" in integration
        assert "inetorgperson" in integration

    def test_load_all_oid_fixtures(self) -> None:
        """Test loading all OID fixtures at once."""
        loader = FlextLdifFixtures.Loader()
        all_fixtures = loader.load_all(FlextLdifFixtures.ServerType.OID)

        assert len(all_fixtures) == 4
        assert FlextLdifFixtures.FixtureType.SCHEMA in all_fixtures
        assert FlextLdifFixtures.FixtureType.ACL in all_fixtures
        assert FlextLdifFixtures.FixtureType.ENTRIES in all_fixtures
        assert FlextLdifFixtures.FixtureType.INTEGRATION in all_fixtures

    def test_get_available_servers(self) -> None:
        """Test getting list of available servers."""
        loader = FlextLdifFixtures.Loader()
        servers = loader.get_available_servers()

        assert FlextLdifFixtures.ServerType.OID in servers

    def test_get_available_fixtures_for_oid(self) -> None:
        """Test getting available fixtures for OID."""
        loader = FlextLdifFixtures.Loader()
        fixtures = loader.get_available_fixtures(FlextLdifFixtures.ServerType.OID)

        assert len(fixtures) == 4
        assert FlextLdifFixtures.FixtureType.SCHEMA in fixtures
        assert FlextLdifFixtures.FixtureType.ACL in fixtures
        assert FlextLdifFixtures.FixtureType.ENTRIES in fixtures
        assert FlextLdifFixtures.FixtureType.INTEGRATION in fixtures

    def test_get_metadata(self) -> None:
        """Test getting fixture metadata."""
        loader = FlextLdifFixtures.Loader()
        metadata = loader.get_metadata(
            FlextLdifFixtures.ServerType.OID, FlextLdifFixtures.FixtureType.SCHEMA
        )

        assert metadata.server_type == FlextLdifFixtures.ServerType.OID
        assert metadata.fixture_type == FlextLdifFixtures.FixtureType.SCHEMA
        assert metadata.line_count > 0
        assert metadata.entry_count > 0
        assert metadata.size_bytes > 0
        assert metadata.file_path.exists()

    def test_fixture_exists(self) -> None:
        """Test checking if fixture exists."""
        loader = FlextLdifFixtures.Loader()

        assert loader.fixture_exists(
            FlextLdifFixtures.ServerType.OID, FlextLdifFixtures.FixtureType.SCHEMA
        )
        assert not loader.fixture_exists(
            FlextLdifFixtures.ServerType.AD, FlextLdifFixtures.FixtureType.SCHEMA
        )


class TestFlextLdifFixturesOID:
    """Test FlextLdifFixtures.OID convenience class."""

    def test_oid_loader_initialization(self) -> None:
        """Test OID loader can be initialized."""
        oid = FlextLdifFixtures.OID()
        assert oid is not None

    def test_oid_schema(self) -> None:
        """Test loading schema via OID convenience class."""
        oid = FlextLdifFixtures.OID()
        schema = oid.schema()

        assert schema
        assert "orclOIDSCExtHost" in schema

    def test_oid_acl(self) -> None:
        """Test loading ACL via OID convenience class."""
        oid = FlextLdifFixtures.OID()
        acl = oid.acl()

        assert acl
        assert "orclaci" in acl

    def test_oid_entries(self) -> None:
        """Test loading entries via OID convenience class."""
        oid = FlextLdifFixtures.OID()
        entries = oid.entries()

        assert entries
        assert "testuser" in entries.lower()

    def test_oid_integration(self) -> None:
        """Test loading integration fixtures via OID convenience class."""
        oid = FlextLdifFixtures.OID()
        integration = oid.integration()

        assert integration
        assert "REAL OID QUIRKS" in integration

    def test_oid_all(self) -> None:
        """Test loading all fixtures via OID convenience class."""
        oid = FlextLdifFixtures.OID()
        all_fixtures = oid.all()

        assert len(all_fixtures) == 4

    def test_oid_metadata(self) -> None:
        """Test getting metadata via OID convenience class."""
        oid = FlextLdifFixtures.OID()
        metadata = oid.metadata(FlextLdifFixtures.FixtureType.SCHEMA)

        assert metadata.server_type == FlextLdifFixtures.ServerType.OID
        assert metadata.line_count > 0


class TestFlextLdifFixturesPytestIntegration:
    """Test pytest fixture integration."""

    def test_oid_fixtures_fixture(self, oid_fixtures: FlextLdifFixtures.OID) -> None:
        """Test using oid_fixtures pytest fixture."""
        schema = oid_fixtures.schema()
        assert "orclOIDSCExtHost" in schema

    def test_oid_schema_fixture(self, oid_schema: str) -> None:
        """Test using oid_schema pytest fixture."""
        assert "attributetypes" in oid_schema
        assert "2.16.840.1.113894" in oid_schema

    def test_oid_acl_fixture(self, oid_acl: str) -> None:
        """Test using oid_acl pytest fixture."""
        assert "orclaci" in oid_acl
        assert "orclentrylevelaci" in oid_acl

    def test_oid_entries_fixture(self, oid_entries: str) -> None:
        """Test using oid_entries pytest fixture."""
        assert "testuser" in oid_entries.lower()
        assert "objectclass:" in oid_entries.lower()

    def test_oid_integration_fixture(self, oid_integration: str) -> None:
        """Test using oid_integration pytest fixture."""
        assert "REAL OID QUIRKS" in oid_integration
        assert "groupofuniquenames" in oid_integration
        assert "inetorgperson" in oid_integration

    def test_fixtures_loader_fixture(
        self, fixtures_loader: FlextLdifFixtures.Loader
    ) -> None:
        """Test using fixtures_loader pytest fixture."""
        servers = fixtures_loader.get_available_servers()
        assert FlextLdifFixtures.ServerType.OID in servers


class TestFlextLdifFixturesIntegrationQuirks:
    """Test real OID quirks in integration fixtures."""

    def test_mixed_case_objectclass(self, oid_integration: str) -> None:
        """Test integration fixtures contain mixed case objectClass quirks."""
        assert "groupofuniquenames" in oid_integration
        assert "groupofUniqueNames" in oid_integration
        assert "groupOfUniqueNames" in oid_integration
        assert "GroupOfUniqueNames" in oid_integration

    def test_mixed_case_inetorgperson(self, oid_integration: str) -> None:
        """Test integration fixtures contain inetOrgPerson case variations."""
        assert "inetorgperson" in oid_integration
        assert "inetOrgPerson" in oid_integration

    def test_mixed_case_container(self, oid_integration: str) -> None:
        """Test integration fixtures contain orclContainer case variations."""
        assert "orclcontainer" in oid_integration
        assert "orclContainer" in oid_integration
        assert "orclcontainerOC" in oid_integration
        assert "orclcontainerOc" in oid_integration

    def test_real_custom_attributes(self, oid_integration: str) -> None:
        """Test integration fixtures contain real custom attributes from Algar."""
        assert "empresa:" in oid_integration
        assert "cpf:" in oid_integration
        assert "contrato:" in oid_integration
        assert "responsavel:" in oid_integration
        assert "tipousuario:" in oid_integration
        assert "calid:" in oid_integration
        assert "vantiveid:" in oid_integration

    def test_real_organizational_structure(self, oid_integration: str) -> None:
        """Test integration fixtures contain real OU structure."""
        assert "ou=temporario" in oid_integration
        assert "ou=associado" in oid_integration
        assert "ou=estagiario" in oid_integration

    def test_complex_acl_patterns(self, oid_integration: str) -> None:
        """Test integration fixtures contain complex ACL patterns."""
        assert "BindMode=" in oid_integration
        assert "guidattr=" in oid_integration
        assert "dnattr=" in oid_integration
        assert "groupattr=" in oid_integration
        assert "filter=(objectclass=" in oid_integration
        assert "added_object_constraint=" in oid_integration

    def test_password_hash_schemes(self, oid_integration: str) -> None:
        """Test integration fixtures contain various password hash schemes."""
        assert "{SSHA}" in oid_integration
        assert "{SASL/MD5}" in oid_integration
        assert "{MD5}" in oid_integration
        assert "{x- orcldbpwd}" in oid_integration
        assert "authpassword;oid:" in oid_integration
        assert "authpassword;orclcommonpwd:" in oid_integration
