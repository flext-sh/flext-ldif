"""Tests for migration pipeline server-specific quirks.

This module tests the FlextLdifMigrationPipeline with server-specific quirk
handling, validating server-to-server transformations including boolean value
conversions and other server-specific attribute transformations during migrations.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import tm

from flext_ldif import (
    FlextLdifMigrationPipeline,
    FlextLdifServersOidConstants,
    FlextLdifServersRfc,
)
from tests import c


class TestsFlextLdifMigrationPipelineQuirks:
    """Test suite for migration pipeline quirks."""

    @pytest.mark.parametrize(
        ("source_server", "target_server", "input_true", "input_false"),
        list(c.Ldif.MIGRATION_BOOLEAN_CASES.values()),
        ids=list(c.Ldif.MIGRATION_BOOLEAN_CASES.keys()),
    )
    def test_oid_boolean_conversion_between_servers(
        self,
        tmp_path: Path,
        source_server: str,
        target_server: str,
        input_true: str,
        input_false: str,
    ) -> None:
        """Test boolean conversion rules during OID and RFC migrations."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        ldif_content = c.Ldif.MIGRATION_BOOLEAN_ENTRY_TEMPLATE.format(
            dn=c.Ldif.DN_TEST_USER,
            objectclass=c.Ldif.NAME_OBJECTCLASS,
            top=c.Ldif.NAME_TOP,
            person=c.Ldif.NAME_PERSON,
            orcluser=c.Ldif.NAME_ORCLUSER,
            cn=c.Ldif.NAME_CN,
            cn_value=c.Ldif.ATTR_VALUE_TEST,
            sn=c.Ldif.NAME_SN,
            sn_value=c.Ldif.ATTR_VALUE_TEST,
            attr_enabled=c.Ldif.ATTR_ORCL_IS_ENABLED,
            attr_locked=c.Ldif.ATTR_ORCL_ACCOUNT_LOCKED,
            val_true=input_true,
            val_false=input_false,
        )
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes(source_server),
            target_server=c.Ldif.ServerTypes(target_server),
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        _ = tm.that(output_file.exists(), eq=True)
        content = output_file.read_text(encoding="utf-8")
        if target_server == c.Ldif.RFC:
            expected_true = c.Ldif.BOOLEAN_OID_TO_RFC[input_true]
            expected_false = c.Ldif.BOOLEAN_OID_TO_RFC[input_false]
        else:
            expected_true = c.Ldif.BOOLEAN_RFC_TO_OID[input_true]
            expected_false = c.Ldif.BOOLEAN_RFC_TO_OID[input_false]
        tm.that(
            content,
            has=f"{c.Ldif.ATTR_ORCL_IS_ENABLED.lower()}: {expected_true}",
        )
        tm.that(
            content,
            has=f"{c.Ldif.ATTR_ORCL_ACCOUNT_LOCKED.lower()}: {expected_false}",
        )
        tm.that(
            f"{c.Ldif.ATTR_ORCL_IS_ENABLED.lower()}: {input_true}" not in content,
            eq=True,
        )
        tm.that(
            f"{c.Ldif.ATTR_ORCL_ACCOUNT_LOCKED.lower()}: {input_false}" not in content,
            eq=True,
        )

    @pytest.mark.parametrize(
        ("source_server", "target_server", "input_attribute", "expected_attribute"),
        list(c.Ldif.MIGRATION_ACL_CASES.values()),
        ids=list(c.Ldif.MIGRATION_ACL_CASES.keys()),
    )
    def test_oid_acl_conversion_between_servers(
        self,
        tmp_path: Path,
        source_server: str,
        target_server: str,
        input_attribute: str,
        expected_attribute: str,
    ) -> None:
        """Test ACL attribute renaming rules during OID and RFC migrations."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        ldif_content = c.Ldif.MIGRATION_ACL_ENTRY_TEMPLATE.format(
            dn=c.Ldif.DN_TEST_USER,
            objectclass=c.Ldif.NAME_OBJECTCLASS,
            top=c.Ldif.NAME_TOP,
            person=c.Ldif.NAME_PERSON,
            cn=c.Ldif.NAME_CN,
            cn_value=c.Ldif.ATTR_VALUE_TEST,
            sn=c.Ldif.NAME_SN,
            sn_value=c.Ldif.ATTR_VALUE_TEST,
            acl_attribute=input_attribute,
            acl_value=c.Ldif.ACL_READ_VALUE,
        )
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes(source_server),
            target_server=c.Ldif.ServerTypes(target_server),
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        _ = tm.that(output_file.exists(), eq=True)
        content = output_file.read_text(encoding="utf-8")
        tm.that(
            content,
            has=f"{expected_attribute}: {c.Ldif.ACL_READ_VALUE}",
        )
        if expected_attribute == FlextLdifServersOidConstants.ORCLACI:
            _ = tm.that(
                not c.Ldif.MIGRATION_ACI_LINE_REGEX.search(content),
                eq=True,
            )
        else:
            tm.that(f"{FlextLdifServersOidConstants.ORCLACI}:" not in content, eq=True)

    def test_oid_schema_dn_conversion(self, tmp_path: Path) -> None:
        """Test OID schema DN conversion (cn=subschemasubentry -> cn=schema)."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        ldif_content = c.Ldif.MIGRATION_SCHEMA_ENTRY_TEMPLATE.format(
            dn=FlextLdifServersOidConstants.SCHEMA_DN_QUIRK,
            objectclass=c.Ldif.NAME_OBJECTCLASS,
            top=c.Ldif.NAME_TOP,
            subschema=c.Ldif.NAME_SUBSCHEMA,
            cn=c.Ldif.NAME_CN,
        )
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
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
        ldif_content = (
            f"dn: {c.Ldif.DN_TEST_USER}\n"
            f"{c.Ldif.NAME_OBJECTCLASS}: {c.Ldif.NAME_TOP}\n"
            f"{c.Ldif.NAME_OBJECTCLASS}: {c.Ldif.NAME_PERSON}\n"
            f"{c.Ldif.NAME_CN}: {c.Ldif.ATTR_VALUE_TEST}\n"
            f"{c.Ldif.ATTR_ORCL_IS_ENABLED}: {c.Ldif.BOOLEAN_TRUE}\n"
        )
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes.RFC,
            target_server=c.Ldif.ServerTypes.OID,
        )
        result = pipeline.execute()
        tm.ok(result)
        output_file = output_dir / "migrated.ldif"
        content = output_file.read_text(encoding="utf-8")
        val_true_oid = c.Ldif.BOOLEAN_RFC_TO_OID[c.Ldif.BOOLEAN_TRUE]
        tm.that(
            content,
            has=f"{c.Ldif.ATTR_ORCL_IS_ENABLED.lower()}: {val_true_oid}",
        )
