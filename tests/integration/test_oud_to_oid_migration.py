"""Behavioral integration tests for OUD to OID migration.

Exercises the OBSERVABLE public contract of the OUD -> OID migration surface:
- ``FlextLdifMigrationPipeline`` end-to-end (source=OUD, target=OID)
- ``FlextLdifServersOud.parse_ldif`` / ``FlextLdifServersOid.write`` round-trip
- DN and entry-count preservation as verified through the public ``ldif`` client

No private attributes, internal collaborators, or line-coverage pokes are
asserted -- only return values, ``r[T]`` outcomes, and public model state.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif import ldif
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from tests import TestsFlextLdifUtilities as u, c

if TYPE_CHECKING:
    from pathlib import Path

    from tests import p

MIN_OUD_ENTRIES = 10


class TestsFlextLdifOudToOidMigration:
    """Behavioral contract of the OUD -> OID migration workflow."""

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create an OUD server instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create an OID server instance."""
        return FlextLdifServersOid()

    @pytest.fixture
    def client(self) -> p.Ldif.LdifClient:
        """Create the public ldif client used to re-parse migrated output."""
        return ldif()

    @pytest.fixture
    def oud_entries(self) -> str:
        """Load the OUD entries LDIF fixture."""
        fixture: str = u.Tests.load(c.Tests.OUD, c.Tests.ENTRIES)
        return fixture

    @pytest.fixture
    def oud_integration(self) -> str:
        """Load the OUD integration LDIF fixture (real entries with DNs)."""
        fixture: str = u.Tests.load(c.Tests.OUD, c.Tests.INTEGRATION)
        return fixture

    @pytest.fixture
    def oud_schema(self) -> str:
        """Load the OUD schema LDIF fixture."""
        fixture: str = u.Tests.load(c.Tests.OUD, c.Tests.SCHEMA)
        return fixture

    @staticmethod
    def _dn_set(entries: object) -> set[str]:
        """Collect whitespace-normalized DN values from parsed entries.

        Migration canonicalizes optional whitespace after RDN separators
        (``, `` -> ``,``); the observable contract is that the RDN component
        set is preserved, so DNs are compared component-wise.
        """
        assert isinstance(entries, list)
        split_re = c.Ldif.DN_SPLIT_OPTIONAL_SPACE_RE
        return {
            ",".join(split_re.split(entry.dn.value))
            for entry in entries
            if getattr(entry, "dn", None) is not None
        }

    # -- End-to-end migration pipeline ------------------------------------

    def test_pipeline_migrates_oud_entries_to_oid_output_file(
        self,
        tmp_path: Path,
        oud_entries: str,
        client: p.Ldif.LdifClient,
    ) -> None:
        """Pipeline OUD->OID writes a non-empty, re-parseable OID LDIF file."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "source.ldif").write_text(oud_entries, encoding="utf-8")

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes.OUD,
            target_server=c.Ldif.ServerTypes.OID,
        )

        result = pipeline.execute()

        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        assert output_file.exists(), "Migration did not produce an output file"
        migrated_content = output_file.read_text(encoding="utf-8")
        assert migrated_content.strip(), "Migrated LDIF is empty"
        reparse = client.parse_ldif(migrated_content)
        tm.ok(reparse)

    @pytest.mark.parametrize(
        "fixture_name",
        [c.Tests.ENTRIES, c.Tests.INTEGRATION],
    )
    def test_pipeline_preserves_dn_set_across_migration(
        self,
        tmp_path: Path,
        client: p.Ldif.LdifClient,
        fixture_name: str,
    ) -> None:
        """Every source DN survives the OUD->OID migration unchanged."""
        source_content = u.Tests.load(c.Tests.OUD, fixture_name)
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "source.ldif").write_text(source_content, encoding="utf-8")

        source_parse = client.parse_ldif(source_content)
        tm.ok(source_parse)
        source_dns = self._dn_set(source_parse.value.entries)

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes.OUD,
            target_server=c.Ldif.ServerTypes.OID,
        )
        result = pipeline.execute()
        tm.ok(result)

        migrated = (output_dir / "migrated.ldif").read_text(encoding="utf-8")
        migrated_parse = client.parse_ldif(migrated)
        tm.ok(migrated_parse)
        migrated_dns = self._dn_set(migrated_parse.value.entries)

        tm.that(migrated_dns, eq=source_dns)

    # -- OUD server public parse contract ---------------------------------

    def test_oud_parse_ldif_returns_expected_entry_count(
        self,
        oud: FlextLdifServersOud,
        oud_entries: str,
    ) -> None:
        """OUD ``parse_ldif`` succeeds and yields the fixture's entries."""
        result = oud.parse_ldif(oud_entries)

        tm.ok(result)
        entries = result.value.entries
        assert len(entries) >= MIN_OUD_ENTRIES, (
            f"Expected >= {MIN_OUD_ENTRIES} entries, got {len(entries)}"
        )

    def test_oud_parse_ldif_on_empty_input_yields_no_entries(
        self,
        oud: FlextLdifServersOud,
    ) -> None:
        """Parsing empty content is a success with zero entries (invariant)."""
        result = oud.parse_ldif("")

        tm.ok(result)
        tm.that(result.value.entries, eq=[])

    def test_oud_parse_ldif_accepts_schema_fixture(
        self,
        oud: FlextLdifServersOud,
        oud_schema: str,
    ) -> None:
        """OUD ``parse_ldif`` handles the schema fixture as a subschema entry."""
        result = oud.parse_ldif(oud_schema)

        tm.ok(result)
        assert result.value.entries, "Schema fixture produced no entries"

    # -- OUD -> OID server round-trip -------------------------------------

    def test_oud_parse_then_oid_write_preserves_dns(
        self,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
        client: p.Ldif.LdifClient,
        oud_integration: str,
    ) -> None:
        """OUD-parsed entries written by OID re-parse to the same DN set."""
        parsed = oud.parse_ldif(oud_integration)
        tm.ok(parsed)
        source_entries = parsed.value.entries
        assert source_entries, "No entries parsed from OUD integration fixture"
        source_dns = self._dn_set(source_entries)

        write_result = oid.write(source_entries)
        tm.ok(write_result)
        written_ldif = write_result.value
        assert isinstance(written_ldif, str) and written_ldif.strip(), (
            "OID write produced empty content"
        )

        reparse = client.parse_ldif(written_ldif)
        tm.ok(reparse)
        tm.that(self._dn_set(reparse.value.entries), eq=source_dns)

    def test_oid_write_is_idempotent_on_dn_set(
        self,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
        oud_integration: str,
    ) -> None:
        """Writing the same OUD entries twice yields the same OID DN set."""
        parsed = oud.parse_ldif(oud_integration)
        tm.ok(parsed)
        entries = parsed.value.entries

        first = oid.write(entries)
        second = oid.write(entries)
        assert first.success and second.success, "Repeated OID writes must succeed"

        first_parse = ldif().parse_ldif(first.value)
        second_parse = ldif().parse_ldif(second.value)
        assert first_parse.success and second_parse.success
        tm.that(
            self._dn_set(first_parse.value.entries),
            eq=self._dn_set(
                second_parse.value.entries,
            ),
        )


__all__: list[str] = [
    "TestsFlextLdifOudToOidMigration",
]
