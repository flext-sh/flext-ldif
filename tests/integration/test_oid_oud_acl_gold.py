"""OID→OUD ACL migration through the public pipeline, against consumer golds.

Each scenario copies the bytes of a consumer-owned OID ACL dump into an input
directory and runs ``FlextLdif().migration_pipeline`` (oid→oud) with the ACL
phase output options: hierarchical entry order and ``changetype: modify`` /
``replace: aci`` records. The written output file must equal the consumer's
gold byte for byte. The gold copies keep one provenance line, which the
comparison drops.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

import pytest

from flext_ldif import FlextLdif
from tests import c, m, tm

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifOidOudAclGold:
    """Gold parity of the public oid→oud migration for ACL entries."""

    GOLD_DIR: ClassVar[Path] = c.Tests.FIXTURES_DIR / "oid" / "acl_gold"
    OUTPUT_NAME: ClassVar[str] = "acls.ldif"

    @pytest.mark.parametrize(
        ("input_name", "gold_name", "base_dn"),
        [
            pytest.param(
                "acl_synth_input.ldif",
                "acl_synth_gold.ldif",
                "dc=ctbc",
                id="synth",
            ),
            pytest.param(
                "aci_dump_input.ldif",
                "aci_dump_gold.ldif",
                "dc=example,dc=invalid",
                id="aci-dump",
            ),
        ],
    )
    def test_migrated_acl_file_equals_gold(
        self,
        tmp_path: Path,
        input_name: str,
        gold_name: str,
        base_dn: str,
    ) -> None:
        """The written ACL phase file equals the gold byte for byte."""
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
