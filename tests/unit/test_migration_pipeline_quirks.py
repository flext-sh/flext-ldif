"""Tests for migration pipeline server-specific quirks.

This module tests the FlextLdifMigrationPipeline with server-specific quirk
handling, validating server-to-server transformations including boolean value
conversions and other server-specific attribute transformations during migrations.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from flext_tests import tm

from flext_ldif import (
    FlextLdifMigrationPipeline,
    FlextLdifServersOidConstants,
    FlextLdifServersRfc,
)
from tests import c, s


class OidTestConstants:
    """Constants for OID boolean conversion tests."""

    RFC_TO_OID_BOOLEAN: Final[Mapping[str, str]] = {"TRUE": "1", "FALSE": "0"}
    OID_TO_RFC_BOOLEAN: Final[Mapping[str, str]] = {"1": "TRUE", "0": "FALSE"}


class TestsFlextLdifMigrationPipelineQuirks(s):
    """Test suite for migration pipeline quirks."""

    def test_oid_boolean_conversion_oid_to_rfc(self, tmp_path: Path) -> None:
        """Test OID boolean conversion (0/1 -> TRUE/FALSE) during OID -> RFC migration."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        attr_enabled = "orclIsEnabled"
        attr_locked = "orclAccountLocked"
        val_true_oid = OidTestConstants.RFC_TO_OID_BOOLEAN["TRUE"]
        val_false_oid = OidTestConstants.RFC_TO_OID_BOOLEAN["FALSE"]
        ldif_content = f"dn: {c.Ldif.DNs.TEST_USER}\n{c.Ldif.Names.OBJECTCLASS}: {c.Ldif.Names.TOP}\n{c.Ldif.Names.OBJECTCLASS}: {c.Ldif.Names.PERSON}\n{c.Ldif.Names.OBJECTCLASS}: orcluser\n{c.Ldif.Names.CN}: test\n{c.Ldif.Names.SN}: test\n{attr_enabled}: {val_true_oid}\n{attr_locked}: {val_false_oid}\n"
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes.OID,
            target_server=c.Ldif.ServerTypes.RFC,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        _ = tm.that(output_file.exists(), eq=True)
        content = output_file.read_text(encoding="utf-8")
        val_true_rfc = OidTestConstants.OID_TO_RFC_BOOLEAN[val_true_oid]
        val_false_rfc = OidTestConstants.OID_TO_RFC_BOOLEAN[val_false_oid]
        tm.that(content, has=f"{attr_enabled.lower()}: {val_true_rfc}")
        tm.that(content, has=f"{attr_locked.lower()}: {val_false_rfc}")
        tm.that(f"{attr_enabled.lower()}: {val_true_oid}" not in content, eq=True)
        tm.that(f"{attr_locked.lower()}: {val_false_oid}" not in content, eq=True)

    def test_oid_boolean_conversion_rfc_to_oid(self, tmp_path: Path) -> None:
        """Test OID boolean conversion (TRUE/FALSE -> 0/1) during RFC -> OID migration."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        attr_enabled = "orclIsEnabled"
        attr_locked = "orclAccountLocked"
        val_true_rfc = "TRUE"
        val_false_rfc = "FALSE"
        ldif_content = f"dn: {c.Ldif.DNs.TEST_USER}\n{c.Ldif.Names.OBJECTCLASS}: {c.Ldif.Names.TOP}\n{c.Ldif.Names.OBJECTCLASS}: {c.Ldif.Names.PERSON}\n{c.Ldif.Names.OBJECTCLASS}: orcluser\n{c.Ldif.Names.CN}: test\n{c.Ldif.Names.SN}: test\n{attr_enabled}: {val_true_rfc}\n{attr_locked}: {val_false_rfc}\n"
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes.RFC,
            target_server=c.Ldif.ServerTypes.OID,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        _ = tm.that(output_file.exists(), eq=True)
        content = output_file.read_text(encoding="utf-8")
        val_true_oid = OidTestConstants.RFC_TO_OID_BOOLEAN[val_true_rfc]
        val_false_oid = OidTestConstants.RFC_TO_OID_BOOLEAN[val_false_rfc]
        tm.that(content, has=f"{attr_enabled.lower()}: {val_true_oid}")
        tm.that(content, has=f"{attr_locked.lower()}: {val_false_oid}")
        tm.that(f"{attr_enabled.lower()}: {val_true_rfc}" not in content, eq=True)
        tm.that(f"{attr_locked.lower()}: {val_false_rfc}" not in content, eq=True)

    def test_oid_acl_conversion_oid_to_rfc(self, tmp_path: Path) -> None:
        """Test OID ACL conversion (orclaci -> aci) during OID -> RFC migration."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        acl_val = "access to entry by * (read)"
        ldif_content = f"dn: {c.Ldif.DNs.TEST_USER}\n{c.Ldif.Names.OBJECTCLASS}: {c.Ldif.Names.TOP}\n{c.Ldif.Names.OBJECTCLASS}: {c.Ldif.Names.PERSON}\n{c.Ldif.Names.CN}: test\n{c.Ldif.Names.SN}: test\n{FlextLdifServersOidConstants.ORCLACI}: {acl_val}\n"
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes.OID,
            target_server=c.Ldif.ServerTypes.RFC,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        _ = tm.that(output_file.exists(), eq=True)
        content = output_file.read_text(encoding="utf-8")
        tm.that(
            (
                f"{FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME}: {acl_val}"
                in content
            ),
            eq=True,
        )
        tm.that(f"{FlextLdifServersOidConstants.ORCLACI}:" not in content, eq=True)

    def test_oid_acl_conversion_rfc_to_oid(self, tmp_path: Path) -> None:
        """Test OID ACL conversion (aci -> orclaci) during RFC -> OID migration."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        acl_val = "access to entry by * (read)"
        ldif_content = f"dn: {c.Ldif.DNs.TEST_USER}\n{c.Ldif.Names.OBJECTCLASS}: {c.Ldif.Names.TOP}\n{c.Ldif.Names.OBJECTCLASS}: {c.Ldif.Names.PERSON}\n{c.Ldif.Names.CN}: test\n{c.Ldif.Names.SN}: test\n{FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME}: {acl_val}\n"
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes.RFC,
            target_server=c.Ldif.ServerTypes.OID,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        _ = tm.that(output_file.exists(), eq=True)
        content = output_file.read_text(encoding="utf-8")
        tm.that(content, has=f"{FlextLdifServersOidConstants.ORCLACI}: {acl_val}")
        _ = tm.that(not re.search(r"(^|\\n)aci:", content), eq=True)

    def test_oid_schema_dn_conversion(self, tmp_path: Path) -> None:
        """Test OID schema DN conversion (cn=subschemasubentry -> cn=schema)."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        ldif_content = f"dn: {FlextLdifServersOidConstants.SCHEMA_DN_QUIRK}\n{c.Ldif.Names.OBJECTCLASS}: {c.Ldif.Names.TOP}\n{c.Ldif.Names.OBJECTCLASS}: subschema\n{c.Ldif.Names.CN}: subschemasubentry\n"
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes.OID,
            target_server=c.Ldif.ServerTypes.RFC,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        _ = tm.that(output_file.exists(), eq=True)
        content = output_file.read_text(encoding="utf-8")
        tm.that(content, has=f"dn: {FlextLdifServersRfc.Constants.SCHEMA_DN}")
        tm.that(
            f"dn: {FlextLdifServersOidConstants.SCHEMA_DN_QUIRK}" not in content,
            eq=True,
        )

    def test_pipeline_enforces_quirks(self, tmp_path: Path) -> None:
        """Test that pipeline enforces quirks even if input looks like c.Ldif.RFC."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        attr_enabled = "orclIsEnabled"
        val_true_rfc = "TRUE"
        ldif_content = f"dn: {c.Ldif.DNs.TEST_USER}\n{c.Ldif.Names.OBJECTCLASS}: {c.Ldif.Names.TOP}\n{c.Ldif.Names.OBJECTCLASS}: {c.Ldif.Names.PERSON}\n{c.Ldif.Names.CN}: test\n{attr_enabled}: {val_true_rfc}\n"
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes.RFC,
            target_server=c.Ldif.ServerTypes.OID,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        content = output_file.read_text(encoding="utf-8")
        val_true_oid = OidTestConstants.RFC_TO_OID_BOOLEAN[val_true_rfc]
        tm.that(content, has=f"{attr_enabled.lower()}: {val_true_oid}")
