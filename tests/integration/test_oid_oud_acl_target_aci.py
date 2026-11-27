"""An OID ACL whose target names the ACL attributes protects ``aci`` on OUD.

``orclaci`` and ``orclentrylevelaci`` become the OUD ``aci`` after
conversion, so a target listing them converts to ``targetattr`` naming
``aci`` once, through the oid→oud pipeline, instead of failing.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_ldif import FlextLdif
from tests import c, m, tm

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifOidOudAclTargetAci:
    """A target naming the OID ACL attributes converts to ``aci``."""

    INPUT: ClassVar[str] = (
        "dn: dc=ctbc\nobjectClass: top\nobjectClass: domain\ndc: ctbc\n"
        "orclaci: access to attr=(orclaci,orclentrylevelaci,description) "
        "by * (none)\n"
    )

    @classmethod
    def test_acl_attribute_target_converts_to_aci(cls, tmp_path: Path) -> None:
        """Both OID ACL attribute names collapse into one ``aci`` target."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "acl.ldif").write_text(cls.INPUT, encoding="utf-8")
        tm.ok(
            FlextLdif()
            .migration_pipeline(
                input_dir=input_dir,
                output_dir=output_dir,
                settings=m.Ldif.TransformConfig.servers(
                    source_server=c.Tests.OID,
                    target_server=c.Tests.OUD,
                    base_dn="dc=ctbc",
                ),
                options=m.Ldif.MigrateOptions(output_filename="acls.ldif"),
            )
            .execute(),
        )
        written = (output_dir / "acls.ldif").read_text(encoding="utf-8")
        acis = [
            line.removeprefix("aci: ")
            for line in written.splitlines()
            if line.startswith("aci: ")
        ]
        tm.that(
            [aci for aci in acis if '(targetattr="aci||description")' in aci],
            empty=False,
        )
        tm.that([aci for aci in acis if "orcl" in aci.split(";")[0]], empty=True)
