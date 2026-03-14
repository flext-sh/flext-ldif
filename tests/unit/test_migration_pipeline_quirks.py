"""Tests for migration pipeline server-specific quirks.

This module tests the FlextLdifMigrationPipeline with server-specific quirk
handling, validating server-to-server transformations including boolean value
conversions and other server-specific attribute transformations during migrations.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from flext_tests import tm

from flext_ldif import FlextLdifMigrationPipeline, c as lib_c
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc
from tests import c, s


class OidTestConstants:
    """Constants for OID boolean conversion tests."""

    RFC_TO_OID_BOOLEAN: Final[dict[str, str]] = {"TRUE": "1", "FALSE": "0"}
    OID_TO_RFC_BOOLEAN: Final[dict[str, str]] = {"1": "TRUE", "0": "FALSE"}


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
        ldif_content = f"dn: {c.DNs.TEST_USER}\n{c.Names.OBJECTCLASS}: {c.Names.TOP}\n{c.Names.OBJECTCLASS}: {c.Names.PERSON}\n{c.Names.OBJECTCLASS}: orcluser\n{c.Names.CN}: test\n{c.Names.SN}: test\n{attr_enabled}: {val_true_oid}\n{attr_locked}: {val_false_oid}\n"
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=lib_c.Ldif.ServerTypes.OID,
            target_server=lib_c.Ldif.ServerTypes.RFC,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        assert output_file.exists(), f"Expected output file to exist: {output_file}"
        content = output_file.read_text(encoding="utf-8")
        val_true_rfc = OidTestConstants.OID_TO_RFC_BOOLEAN[val_true_oid]
        val_false_rfc = OidTestConstants.OID_TO_RFC_BOOLEAN[val_false_oid]
        assert f"{attr_enabled.lower()}: {val_true_rfc}" in content
        assert f"{attr_locked.lower()}: {val_false_rfc}" in content
        assert f"{attr_enabled.lower()}: {val_true_oid}" not in content
        assert f"{attr_locked.lower()}: {val_false_oid}" not in content

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
        ldif_content = f"dn: {c.DNs.TEST_USER}\n{c.Names.OBJECTCLASS}: {c.Names.TOP}\n{c.Names.OBJECTCLASS}: {c.Names.PERSON}\n{c.Names.OBJECTCLASS}: orcluser\n{c.Names.CN}: test\n{c.Names.SN}: test\n{attr_enabled}: {val_true_rfc}\n{attr_locked}: {val_false_rfc}\n"
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=lib_c.Ldif.ServerTypes.RFC,
            target_server=lib_c.Ldif.ServerTypes.OID,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        assert output_file.exists(), f"Expected output file to exist: {output_file}"
        content = output_file.read_text(encoding="utf-8")
        val_true_oid = OidTestConstants.RFC_TO_OID_BOOLEAN[val_true_rfc]
        val_false_oid = OidTestConstants.RFC_TO_OID_BOOLEAN[val_false_rfc]
        assert f"{attr_enabled.lower()}: {val_true_oid}" in content
        assert f"{attr_locked.lower()}: {val_false_oid}" in content
        assert f"{attr_enabled.lower()}: {val_true_rfc}" not in content
        assert f"{attr_locked.lower()}: {val_false_rfc}" not in content

    def test_oid_acl_conversion_oid_to_rfc(self, tmp_path: Path) -> None:
        """Test OID ACL conversion (orclaci -> aci) during OID -> RFC migration."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        acl_val = "access to entry by * (read)"
        ldif_content = f"dn: {c.DNs.TEST_USER}\n{c.Names.OBJECTCLASS}: {c.Names.TOP}\n{c.Names.OBJECTCLASS}: {c.Names.PERSON}\n{c.Names.CN}: test\n{c.Names.SN}: test\n{FlextLdifServersOidConstants.ORCLACI}: {acl_val}\n"
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=lib_c.Ldif.ServerTypes.OID,
            target_server=lib_c.Ldif.ServerTypes.RFC,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        assert output_file.exists(), f"Expected output file to exist: {output_file}"
        content = output_file.read_text(encoding="utf-8")
        assert (
            f"{FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME}: {acl_val}" in content
        )
        assert f"{FlextLdifServersOidConstants.ORCLACI}:" not in content

    def test_oid_acl_conversion_rfc_to_oid(self, tmp_path: Path) -> None:
        """Test OID ACL conversion (aci -> orclaci) during RFC -> OID migration."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        acl_val = "access to entry by * (read)"
        ldif_content = f"dn: {c.DNs.TEST_USER}\n{c.Names.OBJECTCLASS}: {c.Names.TOP}\n{c.Names.OBJECTCLASS}: {c.Names.PERSON}\n{c.Names.CN}: test\n{c.Names.SN}: test\n{FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME}: {acl_val}\n"
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=lib_c.Ldif.ServerTypes.RFC,
            target_server=lib_c.Ldif.ServerTypes.OID,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        assert output_file.exists(), f"Expected output file to exist: {output_file}"
        content = output_file.read_text(encoding="utf-8")
        assert f"{FlextLdifServersOidConstants.ORCLACI}: {acl_val}" in content
        assert not re.search(r"(^|\\n)aci:", content), (
            "Should not have standalone 'aci:' attribute"
        )

    def test_oid_schema_dn_conversion(self, tmp_path: Path) -> None:
        """Test OID schema DN conversion (cn=subschemasubentry -> cn=schema)."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        ldif_content = f"dn: {FlextLdifServersOidConstants.SCHEMA_DN_QUIRK}\n{c.Names.OBJECTCLASS}: {c.Names.TOP}\n{c.Names.OBJECTCLASS}: subschema\n{c.Names.CN}: subschemasubentry\n"
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=lib_c.Ldif.ServerTypes.OID,
            target_server=lib_c.Ldif.ServerTypes.RFC,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        assert output_file.exists(), f"Expected output file to exist: {output_file}"
        content = output_file.read_text(encoding="utf-8")
        assert f"dn: {FlextLdifServersRfc.Constants.SCHEMA_DN}" in content
        assert f"dn: {FlextLdifServersOidConstants.SCHEMA_DN_QUIRK}" not in content

    def test_pipeline_enforces_quirks(self, tmp_path: Path) -> None:
        """Test that pipeline enforces quirks even if input looks like c.RFC."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        attr_enabled = "orclIsEnabled"
        val_true_rfc = "TRUE"
        ldif_content = f"dn: {c.DNs.TEST_USER}\n{c.Names.OBJECTCLASS}: {c.Names.TOP}\n{c.Names.OBJECTCLASS}: {c.Names.PERSON}\n{c.Names.CN}: test\n{attr_enabled}: {val_true_rfc}\n"
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=lib_c.Ldif.ServerTypes.RFC,
            target_server=lib_c.Ldif.ServerTypes.OID,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        content = output_file.read_text(encoding="utf-8")
        val_true_oid = OidTestConstants.RFC_TO_OID_BOOLEAN[val_true_rfc]
        assert f"{attr_enabled.lower()}: {val_true_oid}" in content
