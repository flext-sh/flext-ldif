"""OID→OUD ACL migration through the public pipeline, against expected outputs.

Each scenario copies an OID ACL input fixture into an input directory and runs
``FlextLdif().migration_pipeline`` (oid→oud) with the ACL phase output
options: hierarchical entry order and ``changetype: modify`` / ``replace:
aci`` records. The written output file must equal the expected output byte
for byte; the expected file keeps one provenance line, which the comparison
drops. The inputs derive from devops-oud-iac fixtures (their provenance lines
record the source and any amendment); the expected outputs are flext-ldif's
own conversion under the documented OID semantics (OID-30 §30.1.6.2: union of
grants minus union of denials per ACI) with every denial rendered as an OUD
``deny`` (OUD §9.1.4), not the consumer's gold. Group subjects convert only
for the OID security groups the input itself carries.

The per-subject outcomes recorded on ``entry.metadata.acl_conversion`` must
match ``*_outcomes.tsv``: for every rule of every entry, in output order, the
count of each outcome kind — deny-only rules included.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar

from flext_ldif import FlextLdif
from tests import c, m, p, tm, u

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifOidOudAclGold:
    """Expected-output parity of the public oid→oud migration for ACL entries."""

    GOLD_DIR: ClassVar[Path] = c.Tests.FIXTURES_DIR / "oid" / "acl_gold"
    OUTPUT_NAME: ClassVar[str] = "acls.ldif"

    _KINDS: ClassVar[tuple[c.Ldif.AclSubjectOutcomeKind, ...]] = (
        c.Ldif.AclSubjectOutcomeKind.GRANTED,
        c.Ldif.AclSubjectOutcomeKind.CANCELLED,
        c.Ldif.AclSubjectOutcomeKind.DENIED_ALL,
        c.Ldif.AclSubjectOutcomeKind.DENIED,
        c.Ldif.AclSubjectOutcomeKind.OUT_OF_SCOPE,
    )

    @classmethod
    def _outcome_rows(
        cls,
        entries: Sequence[p.Ldif.Entry],
    ) -> list[tuple[str, ...]]:
        """Count outcome kinds for every rule of every converted entry.

        Returns:
            Rows of DN followed by one count per ``_KINDS`` kind.

        """
        rows: list[tuple[str, ...]] = []
        for entry in entries:
            conversion = entry.metadata.acl_conversion if entry.metadata else None
            if conversion is None:
                continue
            for rule in conversion.rules:
                kinds = [outcome.kind for outcome in rule.outcomes]
                rows.append((
                    entry.dn_str,
                    *(str(kinds.count(kind)) for kind in cls._KINDS),
                ))
        return rows

    def _expected_rows(self, outcomes_name: str) -> list[tuple[str, ...]]:
        """Read the expected per-rule outcome counts.

        Returns:
            Rows of DN followed by one count per ``_KINDS`` kind.

        """
        lines = (self.GOLD_DIR / outcomes_name).read_text(encoding="utf-8")
        return [tuple(line.split("\t")) for line in lines.splitlines()[1:]]

    @c.Tests.MARK.parametrize(
        ("input_name", "gold_name", "outcomes_name", "base_dn"),
        [
            u.Tests.param(
                "acl_synth_input.ldif",
                "acl_synth_gold.ldif",
                "acl_synth_outcomes.tsv",
                "dc=ctbc",
                id="synth",
            ),
            u.Tests.param(
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
        """The written ACL file and the typed outcomes match the expected output."""
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
