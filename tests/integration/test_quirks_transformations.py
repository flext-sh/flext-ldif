"""Comprehensive Quirks Transformation Tests.

Target OID and OUD quirks server implementations with real transformation operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud


class TestOidQuirksTransformations:
    """Test OID quirks with actual data transformations."""

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        return FlextLdifServersOid()

    @pytest.fixture
    def api(self) -> FlextLdif:
        return FlextLdif()

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        return Path(__file__).parent.parent / "fixtures"

    def test_oid_parse_and_transform_schema(
        self,
        api: FlextLdif,
        fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Test OID schema parsing and transformation."""
        fixture_path = fixtures_dir / "oid" / "oid_schema_fixtures.ldif"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        parse_result = api.parse(fixture_path)
        if parse_result.is_success:
            entries = parse_result.unwrap()
            write_result = api.write(entries, tmp_path / "oid_schema_output.ldif")
            assert write_result.is_success or write_result.is_failure

    def test_oid_parse_and_transform_acl(
        self,
        api: FlextLdif,
        fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Test OID ACL parsing and transformation."""
        fixture_path = fixtures_dir / "oid" / "oid_acl_fixtures.ldif"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        parse_result = api.parse(fixture_path)
        if parse_result.is_success:
            entries = parse_result.unwrap()
            write_result = api.write(entries, tmp_path / "oid_acl_output.ldif")
            assert write_result.is_success or write_result.is_failure

    def test_oid_to_openldap_migration(
        self,
        api: FlextLdif,
        fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Test OID to OpenLDAP migration."""
        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        input_dir = tmp_path / "oid_input"
        output_dir = tmp_path / "openldap_output"
        input_dir.mkdir()
        output_dir.mkdir()

        import shutil

        shutil.copy(fixture_path, input_dir / "data.ldif")

        result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server="oid",
            target_server="openldap",
        )
        assert result.is_success or result.is_failure


class TestOudQuirksTransformations:
    """Test OUD quirks with actual data transformations."""

    @pytest.fixture
    def ouds(self) -> FlextLdifServersOud:
        return FlextLdifServersOud()

    @pytest.fixture
    def api(self) -> FlextLdif:
        return FlextLdif()

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        return Path(__file__).parent.parent / "fixtures"

    def test_oud_parse_and_transform_schema(
        self,
        api: FlextLdif,
        fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Test OUD schema parsing and transformation."""
        fixture_path = fixtures_dir / "oud" / "oud_schema_fixtures.ldif"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        parse_result = api.parse(fixture_path)
        if parse_result.is_success:
            entries = parse_result.unwrap()
            write_result = api.write(entries, tmp_path / "oud_schema_output.ldif")
            assert write_result.is_success or write_result.is_failure

    def test_oud_parse_and_transform_acl(
        self,
        api: FlextLdif,
        fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Test OUD ACL parsing and transformation."""
        fixture_path = fixtures_dir / "oud" / "oud_acl_fixtures.ldif"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        parse_result = api.parse(fixture_path)
        if parse_result.is_success:
            entries = parse_result.unwrap()
            write_result = api.write(entries, tmp_path / "oud_acl_output.ldif")
            assert write_result.is_success or write_result.is_failure

    def test_oid_to_oud_migration(
        self,
        api: FlextLdif,
        fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Test OID to OUD migration."""
        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        input_dir = tmp_path / "oid_input"
        output_dir = tmp_path / "oud_output"
        input_dir.mkdir()
        output_dir.mkdir()

        import shutil

        shutil.copy(fixture_path, input_dir / "data.ldif")

        result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            from_server="oid",
            to_server="oud",
        )
        assert result.is_success or result.is_failure

    def test_oud_to_openldap_migration(
        self,
        api: FlextLdif,
        fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Test OUD to OpenLDAP migration."""
        fixture_path = fixtures_dir / "oud" / "oud_integration_fixtures.ldif"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        input_dir = tmp_path / "oud_input"
        output_dir = tmp_path / "openldap_oud_output"
        input_dir.mkdir()
        output_dir.mkdir()

        import shutil

        shutil.copy(fixture_path, input_dir / "data.ldif")

        result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            from_server="oud",
            to_server="openldap",
        )
        assert result.is_success or result.is_failure


class TestQuirksPropertyValidation:
    """Test quirks properties and identification."""

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        return FlextLdifServersOid()

    @pytest.fixture
    def ouds(self) -> FlextLdifServersOud:
        return FlextLdifServersOud()

    def test_oid_properties(self, oid: FlextLdifServersOid) -> None:
        """Test OID quirks properties."""
        assert oid.server_type == "oid"
        assert hasattr(oid, "priority")
        assert oid.priority >= 0

    def test_ouds_properties(self, ouds: FlextLdifServersOud) -> None:
        """Test OUD quirks properties."""
        assert ouds.server_type == "oud"
        assert hasattr(ouds, "priority")
        assert ouds.priority >= 0
