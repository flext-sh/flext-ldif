"""OID→OUD ACL migration through the public pipeline, against consumer golds.

Each scenario copies the bytes of a consumer-owned OID ACL dump into an input
directory and runs ``FlextLdif().migration_pipeline`` (oid→oud) with the ACL
phase output options: hierarchical entry order and ``changetype: modify`` /
``replace: aci`` records. The written output file must equal the consumer's
gold byte for byte. The gold copies keep one provenance line, which the
comparison drops.

The per-subject outcomes recorded on ``entry.metadata.acl_conversion`` must
match the conversion notes of the same gold: for each emitted aci (first
occurrence after deduplication), the gold's ``DE`` lines count the GRANTED
subjects, its ``EXCL`` lines the ``by * (none)`` subjects, and its section 6.8
lines the complemented granted subjects. ``*_outcomes.tsv`` holds those counts,
extracted from the
original gold before its report text was stripped.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

import pytest

from flext_ldif import FlextLdif
from flext_ldif.servers import FlextLdifServersOidAclPipeline
from tests import c, m, tm

if TYPE_CHECKING:
    from pathlib import Path

from tests import t


class TestsFlextLdifOidOudAclGold:
    """Gold parity of the public oid→oud migration for ACL entries."""

    GOLD_DIR: ClassVar[Path] = c.Tests.FIXTURES_DIR / "oid" / "acl_gold"
    OUTPUT_NAME: ClassVar[str] = "acls.ldif"

    @staticmethod
    def _outcome_rows(
        entries: t.SequenceOf[m.Ldif.Entry],
    ) -> list[tuple[str, int, int, int, int]]:
        """Count outcome kinds for each emitted aci, first occurrence only.

        Returns:
            Rows of DN, granted, deny-none, complemented and other kinds.

        """
        kind = c.Ldif.AclSubjectOutcomeKind
        rows: list[tuple[str, int, int, int, int]] = []
        for entry in entries:
            conversion = entry.metadata.acl_conversion if entry.metadata else None
            if conversion is None:
                continue
            seen: set[str] = set()
            for rule in conversion.rules:
                rendered = FlextLdifServersOidAclPipeline.render_aci_values((rule,))
                if not rendered or rendered[0] in seen:
                    continue
                seen.add(rendered[0])
                kinds = [outcome.kind for outcome in rule.outcomes]
                granted = kinds.count(kind.GRANTED)
                deny_none = kinds.count(kind.EXCLUDED_DENY_NONE)
                rows.append((
                    entry.dn_str,
                    granted,
                    deny_none,
                    sum(outcome.complement_calculated for outcome in rule.outcomes),
                    len(kinds) - granted - deny_none,
                ))
        return rows

    def _expected_rows(
        self, outcomes_name: str
    ) -> list[tuple[str, int, int, int, int]]:
        """Read the gold-derived outcome counts (no other kind is recorded).

        Returns:
            Rows of DN, granted, deny-none, complemented and zero others.

        """
        lines = (self.GOLD_DIR / outcomes_name).read_text(encoding="utf-8")
        rows: list[tuple[str, int, int, int, int]] = []
        for line in lines.splitlines()[1:]:
            dn, granted, deny_none, complement = line.split("\t")
            rows.append((dn, int(granted), int(deny_none), int(complement), 0))
        return rows

    @pytest.mark.parametrize(
        ("input_name", "gold_name", "outcomes_name", "base_dn"),
        [
            pytest.param(
                "acl_synth_input.ldif",
                "acl_synth_gold.ldif",
                "acl_synth_outcomes.tsv",
                "dc=ctbc",
                id="synth",
            ),
            pytest.param(
                "aci_dump_input.ldif",
                "aci_dump_gold.ldif",
                "aci_dump_outcomes.tsv",
                "dc=example,dc=invalid",
                id="aci-dump",
            ),
        ],
    )
    def test_migrated_acl_file_and_outcomes_equal_gold(
        self,
        tmp_path: Path,
        input_name: str,
        gold_name: str,
        outcomes_name: str,
        base_dn: str,
    ) -> None:
        """The written ACL file and the typed outcomes both match the gold."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / input_name).write_bytes((self.GOLD_DIR / input_name).read_bytes())

        migrated = tm.ok(
            FlextLdif()
            .migration_pipeline(
                input_dir=input_dir,
                output_dir=output_dir,
                settings=m.Ldif.TransformConfig.servers(
                    source_server=c.Tests.OID,
                    target_server=c.Tests.OUD,
                    base_dn=base_dn,
                ),
                options=m.Ldif.MigrateOptions(
                    output_filename=self.OUTPUT_NAME,
                    sort_entries_hierarchically=True,
                    format_options=m.Ldif.WriteFormatOptions(
                        fold_long_lines=False,
                        ldif_changetype=c.Ldif.ChangeType.MODIFY,
                        ldif_modify_operation=c.Ldif.ChangeOperation.REPLACE,
                    ),
                ),
            )
            .execute(),
        )

        gold_lines = (self.GOLD_DIR / gold_name).read_bytes().split(b"\n")[1:]
        tm.that(migrated.output_files, eq=[str(output_dir / self.OUTPUT_NAME)])
        tm.that(
            (output_dir / self.OUTPUT_NAME).read_bytes().split(b"\n"),
            eq=gold_lines,
        )
        tm.that(
            self._outcome_rows(migrated.entries),
            eq=self._expected_rows(outcomes_name),
        )
