"""OID→OUD ACL conversion through the public migration pipeline, against golds.

Each scenario feeds the bytes of a consumer-owned OID input through
``FlextLdif().migration_pipeline`` (oid→oud) and compares the migrated ``aci``
values, per DN and in DN order, byte-for-byte with the ACIs of the consumer's
gold output. The gold files are scenario data copied with a provenance line.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_ldif import FlextLdif
from tests import c, m, tm

if TYPE_CHECKING:
    from pathlib import Path

    from tests import t


class TestsFlextLdifOidOudAclGold:
    """Gold parity of the public oid→oud migration for ACL entries."""

    GOLD_DIR = c.Tests.FIXTURES_DIR / "oid" / "acl_gold"

    @staticmethod
    def _acis_by_dn(
        entries: t.SequenceOf[m.Ldif.Entry],
    ) -> list[tuple[str, list[str]]]:
        pairs: list[tuple[str, list[str]]] = []
        for entry in entries:
            values = [
                value
                for name, attr_values in entry.attributes_dict.items()
                if name.lower() == c.Ldif.ACI_ATTR_NAME
                for value in attr_values
            ]
            if values:
                pairs.append((entry.dn_str, values))
        return pairs

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
    def test_migrated_acis_equal_gold(
        self,
        tmp_path: Path,
        input_name: str,
        gold_name: str,
        base_dn: str,
    ) -> None:
        """Migrated aci values equal the gold, byte for byte and in DN order."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / input_name).write_bytes((self.GOLD_DIR / input_name).read_bytes())
        api = FlextLdif()
        migrated = tm.ok(
            api.migration_pipeline(
                input_dir=input_dir,
                output_dir=output_dir,
                settings=m.Ldif.TransformConfig.servers(
                    source_server=c.Tests.OID,
                    target_server=c.Tests.OUD,
                    base_dn=base_dn,
                ),
            ).execute(),
        )
        gold = tm.ok(
            api.parse_ldif(self.GOLD_DIR / gold_name, server_type=c.Tests.RFC),
        )

        tm.that(
            self._acis_by_dn(migrated.entries),
            eq=self._acis_by_dn(gold.entries),
        )
