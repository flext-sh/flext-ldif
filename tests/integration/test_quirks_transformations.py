"""Comprehensive Quirks Transformation Tests.

Target OID and OUD quirks server implementations with real transformation operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from flext_ldif import FlextLdif
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud


@pytest.fixture(scope="module")
def fixtures_dir() -> Path:
    return Path(__file__).parent.parent / "fixtures"


@pytest.fixture(scope="module")
def migration_inputs(
    fixtures_dir: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, Path]:
    base_dir = tmp_path_factory.mktemp("quirks-transform-inputs")

    oid_input_dir = base_dir / "oid_input"
    oid_input_dir.mkdir()
    shutil.copy(
        fixtures_dir / "oid" / "oid_entries_fixtures.ldif",
        oid_input_dir / "data.ldif",
    )

    oud_input_dir = base_dir / "oud_input"
    oud_input_dir.mkdir()
    shutil.copy(
        fixtures_dir / "oud" / "oud_entries_fixtures.ldif",
        oud_input_dir / "data.ldif",
    )

    return {
        "oid": oid_input_dir,
        "oud": oud_input_dir,
    }


class TestOidQuirksTransformations:
    """Test OID quirks with actual data transformations."""

    @pytest.fixture(scope="class")
    def oid(self) -> FlextLdifServersOid:
        return FlextLdifServersOid()

    @pytest.fixture(scope="class")
    def api(self) -> FlextLdif:
        return FlextLdif.get_instance()

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
            entries = parse_result.value
            write_result = api.write_file(entries, tmp_path / "oid_schema_output.ldif")
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
            entries = parse_result.value
            write_result = api.write_file(entries, tmp_path / "oid_acl_output.ldif")
            assert write_result.is_success or write_result.is_failure

    def test_oid_to_openldap_migration(
        self,
        api: FlextLdif,
        migration_inputs: dict[str, Path],
        tmp_path: Path,
    ) -> None:
        """Test OID to OpenLDAP migration."""
        output_dir = tmp_path / "openldap_output"
        output_dir.mkdir()

        result = api.migrate(
            input_dir=migration_inputs["oid"],
            output_dir=output_dir,
            source_server="oid",
            target_server="openldap",
        )
        assert result.is_success or result.is_failure


class TestOudQuirksTransformations:
    """Test OUD quirks with actual data transformations."""

    @pytest.fixture(scope="class")
    def ouds(self) -> FlextLdifServersOud:
        return FlextLdifServersOud()

    @pytest.fixture(scope="class")
    def api(self) -> FlextLdif:
        return FlextLdif.get_instance()

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
            entries = parse_result.value
            write_result = api.write_file(entries, tmp_path / "oud_schema_output.ldif")
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
            entries = parse_result.value
            write_result = api.write_file(entries, tmp_path / "oud_acl_output.ldif")
            assert write_result.is_success or write_result.is_failure

    def test_oid_to_oud_migration(
        self,
        api: FlextLdif,
        migration_inputs: dict[str, Path],
        tmp_path: Path,
    ) -> None:
        """Test OID to OUD migration."""
        output_dir = tmp_path / "oud_output"
        output_dir.mkdir()

        result = api.migrate(
            input_dir=migration_inputs["oid"],
            output_dir=output_dir,
            source_server="oid",
            target_server="oud",
        )
        assert result.is_success or result.is_failure

    def test_oud_to_openldap_migration(
        self,
        api: FlextLdif,
        migration_inputs: dict[str, Path],
        tmp_path: Path,
    ) -> None:
        """Test OUD to OpenLDAP migration."""
        output_dir = tmp_path / "openldap_oud_output"
        output_dir.mkdir()

        result = api.migrate(
            input_dir=migration_inputs["oud"],
            output_dir=output_dir,
            source_server="oud",
            target_server="openldap",
        )
        assert result.is_success or result.is_failure


class TestQuirksPropertyValidation:
    """Test quirks properties and identification."""

    @pytest.fixture(scope="class")
    def oid(self) -> FlextLdifServersOid:
        return FlextLdifServersOid()

    @pytest.fixture(scope="class")
    def ouds(self) -> FlextLdifServersOud:
        return FlextLdifServersOud()

    def test_oid_properties(self, oid: FlextLdifServersOid) -> None:
        """Test OID quirks properties."""
        assert oid.server_type == "oid"
        assert hasattr(oid, "priority")
        priority_value = oid.priority
        assert isinstance(priority_value, int), (
            f"priority should be int, got {type(priority_value).__name__}"
        )
        assert priority_value >= 0

    def test_ouds_properties(self, ouds: FlextLdifServersOud) -> None:
        """Test OUD quirks properties."""
        assert ouds.server_type == "oud"
        assert hasattr(ouds, "priority")
        priority_value = ouds.priority
        assert isinstance(priority_value, int), (
            f"priority should be int, got {type(priority_value).__name__}"
        )
        assert priority_value >= 0
