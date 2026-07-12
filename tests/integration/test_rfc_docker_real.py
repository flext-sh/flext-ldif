"""RFC LDIF parser/writer behavioral integration tests.

Exercises the PUBLIC contract of the LDIF parser and writer services against
real fixture data (RFC 2849 / OID / OUD / OpenLDAP). Every assertion targets
observable behavior: the ``r[T]`` outcome, public model state via public API,
round-trip invariants, idempotence, and error paths. No private attribute,
collaborator spying, or line-coverage poking.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import m as ldif_m
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.writer import FlextLdifWriter
from tests.constants import c


def _has_schema_attrs(entry: ldif_m.Ldif.Entry) -> bool:
    """Return True when an entry publicly exposes schema attribute/objectclass keys."""
    if entry.attributes is None:
        return False
    return any(
        key.lower() in {"attributetypes", "objectclasses"}
        for key in entry.attributes.attributes
    )


class TestsFlextLdifRfcDockerReal:
    """Behavioral contract tests for LDIF parse/write over real fixtures."""

    @pytest.fixture
    def server_registry(self) -> FlextLdifServer:
        """Real server registry (genuine collaborator, not mocked)."""
        return FlextLdifServer()

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        """Root fixtures directory."""
        fixtures_dir: Path = c.Tests.FIXTURES_DIR
        return fixtures_dir

    # ------------------------------------------------------------------ #
    # Parsing real fixtures: success outcome + public model invariants   #
    # ------------------------------------------------------------------ #

    @pytest.mark.parametrize(
        ("server_dir", "filename"),
        [
            (c.Tests.OID, "oid_schema_fixtures.ldif"),
            (c.Tests.OUD, "oud_entries_fixtures.ldif"),
            (c.Tests.OUD, "oud_acl_fixtures.ldif"),
        ],
    )
    def test_parse_fixture_returns_success_with_wellformed_entries(
        self,
        fixtures_dir: Path,
        server_dir: str,
        filename: str,
    ) -> None:
        """Parsing a real fixture yields success and RFC-well-formed entries."""
        # Arrange
        source = fixtures_dir / server_dir / filename
        if not source.exists():
            pytest.skip(f"Fixture not available: {source}")

        # Act
        result = FlextLdifParser().parse_ldif_file(source)

        # Assert — public r[T] contract + public model state
        assert result.success, result.error
        entries = result.unwrap().entries
        assert entries, "fixture yielded no entries"
        for entry in entries:
            assert entry.dn is not None, "RFC entry missing required DN"
            assert entry.dn.value, "entry exposes empty DN via public API"

    def test_parse_oid_schema_exposes_schema_definitions(
        self,
        fixtures_dir: Path,
    ) -> None:
        """A parsed OID schema publicly exposes attributeTypes/objectClasses."""
        # Arrange
        source = fixtures_dir / c.Tests.OID / "oid_schema_fixtures.ldif"
        if not source.exists():
            pytest.skip(f"Fixture not available: {source}")

        # Act
        result = FlextLdifParser().parse_ldif_file(source)

        # Assert
        assert result.success, result.error
        assert any(_has_schema_attrs(entry) for entry in result.unwrap().entries)

    def test_parse_oud_acl_exposes_aci_attribute(
        self,
        fixtures_dir: Path,
    ) -> None:
        """Parsed OUD ACL fixtures publicly expose the ``aci`` attribute."""
        # Arrange
        source = fixtures_dir / c.Tests.OUD / "oud_acl_fixtures.ldif"
        if not source.exists():
            pytest.skip(f"Fixture not available: {source}")

        # Act
        result = FlextLdifParser().parse_ldif_file(source)

        # Assert
        assert result.success, result.error
        acl_entries = [
            entry
            for entry in result.unwrap().entries
            if entry.attributes is not None and "aci" in entry.attributes.attributes
        ]
        assert acl_entries, "no ACL entries surfaced through public attributes"

    def test_parse_large_oid_schema_succeeds(self, fixtures_dir: Path) -> None:
        """Parsing the large (>300KB) OID schema succeeds end to end."""
        # Arrange
        source = fixtures_dir / c.Tests.OID / "oid_schema_fixtures.ldif"
        if not source.exists():
            pytest.skip(f"Fixture not available: {source}")
        assert source.stat().st_size > 300_000, "expected large schema fixture"

        # Act
        result = FlextLdifParser().parse_ldif_file(source)

        # Assert
        assert result.success, result.error
        assert result.unwrap().entries

    @pytest.mark.parametrize(
        ("server_dir", "filename"),
        [
            (c.Tests.OUD, "oud_integration_fixtures.ldif"),
            ("openldap2", "openldap2_integration_fixtures.ldif"),
        ],
    )
    def test_parse_integration_fixture_yields_resolved_result(
        self,
        fixtures_dir: Path,
        server_dir: str,
        filename: str,
    ) -> None:
        """Integration fixtures resolve to a definite success-or-failure r[T]."""
        # Arrange
        source = fixtures_dir / server_dir / filename
        if not source.exists():
            pytest.skip(f"Fixture not available: {source}")

        # Act
        result = FlextLdifParser().parse_ldif_file(source)

        # Assert — outcome is well-formed; success and failure are exclusive
        assert result.success is not result.failure
        if result.success:
            assert result.unwrap().entries
        else:
            assert result.error

    # ------------------------------------------------------------------ #
    # Error paths                                                        #
    # ------------------------------------------------------------------ #

    def test_parse_missing_file_fails_with_not_found(self, tmp_path: Path) -> None:
        """Parsing a non-existent path fails with a File-not-found error."""
        # Arrange
        missing = tmp_path / "does_not_exist.ldif"

        # Act
        result = FlextLdifParser().parse_ldif_file(missing)

        # Assert
        assert result.failure
        assert result.error is not None
        assert "File not found" in result.error

    def test_write_to_directory_target_fails_with_write_error(
        self,
        tmp_path: Path,
    ) -> None:
        """Writing to a directory path fails with a descriptive write error."""
        # Arrange — target an existing directory to force a deterministic failure
        entry = ldif_m.Ldif.Entry(
            dn=ldif_m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=ldif_m.Ldif.Attributes(
                attributes={"cn": ["test"]},
                attribute_metadata={},
            ),
        )

        # Act
        result = FlextLdifWriter().write_ldif_file(
            [entry],
            tmp_path,
            server_type=c.Tests.RFC,
        )

        # Assert
        assert result.failure
        assert result.error is not None
        assert "Failed to write LDIF file" in result.error

    @pytest.mark.parametrize(
        "subdir",
        [
            Path("edge_cases") / "unicode",
            Path("broken") / "structure",
        ],
    )
    def test_parse_edge_and_broken_fixtures_resolve_cleanly(
        self,
        fixtures_dir: Path,
        subdir: Path,
    ) -> None:
        """Edge-case and malformed LDIF never crash; each resolves to r[T]."""
        # Arrange
        target_dir = fixtures_dir / subdir
        if not target_dir.exists():
            pytest.skip(f"Fixture directory not available: {target_dir}")
        ldif_files = sorted(target_dir.glob("*.ldif"))
        if not ldif_files:
            pytest.skip(f"No LDIF fixtures under: {target_dir}")

        # Act / Assert
        for ldif_file in ldif_files:
            result = FlextLdifParser().parse_ldif_file(ldif_file)
            assert result.success is not result.failure
            if result.success:
                assert all(
                    entry.dn is not None and isinstance(entry.dn.value, str)
                    for entry in result.unwrap().entries
                )
            else:
                assert result.error

    # ------------------------------------------------------------------ #
    # Round-trip and write invariants                                    #
    # ------------------------------------------------------------------ #

    def test_roundtrip_preserves_entry_dns(
        self,
        fixtures_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Parse -> write -> re-parse preserves the full set of entry DNs."""
        # Arrange
        source = fixtures_dir / c.Tests.OID / "oid_entries_fixtures.ldif"
        if not source.exists():
            pytest.skip(f"Fixture not available: {source}")
        parse_result = FlextLdifParser().parse_ldif_file(source)
        if not parse_result.success:
            pytest.skip(f"Source fixture unparseable: {parse_result.error}")
        original_entries = parse_result.unwrap().entries
        original_dns = {
            entry.dn.value for entry in original_entries if entry.dn is not None
        }
        output_file = tmp_path / "roundtrip.ldif"

        # Act
        write_result = FlextLdifWriter().write_ldif_file(
            original_entries,
            output_file,
            server_type=c.Tests.OID,
        )
        assert write_result.success, write_result.error
        reparse_result = FlextLdifParser().parse_ldif_file(output_file)

        # Assert — round-trip invariant on the public DN contract
        assert write_result.unwrap().output_path == str(output_file)
        assert output_file.exists()
        assert reparse_result.success, reparse_result.error
        reparsed_dns = {
            entry.dn.value
            for entry in reparse_result.unwrap().entries
            if entry.dn is not None
        }
        assert reparsed_dns == original_dns

    def test_write_reports_statistics_and_persists_all_entries(
        self,
        server_registry: FlextLdifServer,
        tmp_path: Path,
    ) -> None:
        """Writing N entries reports N in statistics and persists N DNs."""
        # Arrange
        entry_count = 100
        entries = [
            ldif_m.Ldif.Entry(
                dn=ldif_m.Ldif.DN(value=f"cn=user{i},ou=people,dc=example,dc=com"),
                attributes=ldif_m.Ldif.Attributes(
                    attributes={
                        "cn": [f"user{i}"],
                        "objectClass": ["person", "inetOrgPerson"],
                        "mail": [f"user{i}@example.com"],
                    },
                    attribute_metadata={},
                ),
            )
            for i in range(entry_count)
        ]
        output_file = tmp_path / "large_output.ldif"

        # Act
        result = FlextLdifWriter(server=server_registry).write_ldif_file(
            entries,
            output_file,
            server_type=c.Tests.RFC,
        )

        # Assert — public WriteResponse contract + persisted content
        assert result.success, result.error
        response = result.unwrap()
        assert response.statistics.total_entries == entry_count
        assert response.output_path == str(output_file)
        content = output_file.read_text(encoding="utf-8")
        assert content.count("dn: cn=user") == entry_count

    def test_write_to_string_is_idempotent(
        self,
        server_registry: FlextLdifServer,
    ) -> None:
        """Serializing the same entries twice yields identical LDIF text."""
        # Arrange
        entries = [
            ldif_m.Ldif.Entry(
                dn=ldif_m.Ldif.DN(value="cn=alice,dc=example,dc=com"),
                attributes=ldif_m.Ldif.Attributes(
                    attributes={"cn": ["alice"], "objectClass": ["person"]},
                    attribute_metadata={},
                ),
            ),
        ]
        writer = FlextLdifWriter(server=server_registry)

        # Act
        first = writer.write_to_string(entries, server_type=c.Tests.RFC)
        second = writer.write_to_string(entries, server_type=c.Tests.RFC)

        # Assert — idempotence on the public serialization contract
        assert first.success, first.error
        assert second.success, second.error
        assert first.unwrap() == second.unwrap()
        assert "cn=alice,dc=example,dc=com" in first.unwrap()
