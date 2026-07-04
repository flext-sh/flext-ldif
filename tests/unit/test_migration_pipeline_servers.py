"""Tests for migration pipeline server-specific servers.

This module tests the FlextLdifMigrationPipeline with server-specific server
handling, validating server-to-server transformations including boolean value
conversions and other server-specific attribute transformations during migrations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from tests.constants import c

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifMigrationPipelineServers:
    """Test suite for migration pipeline servers."""

    @pytest.mark.parametrize(
        ("source_server", "target_server", "input_true", "input_false"),
        list(c.Tests.MIGRATION_BOOLEAN_CASES.values()),
        ids=list(c.Tests.MIGRATION_BOOLEAN_CASES.keys()),
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
        ldif_content = c.Tests.MIGRATION_BOOLEAN_ENTRY_TEMPLATE.format(
            dn=c.Tests.DN_TEST_USER,
            objectclass=c.Tests.NAME_OBJECTCLASS,
            top=c.Tests.NAME_TOP,
            person=c.Tests.NAME_PERSON,
            orcluser=c.Tests.NAME_ORCLUSER,
            cn=c.Tests.NAME_CN,
            cn_value=c.Tests.ATTR_VALUE_TEST,
            sn=c.Tests.NAME_SN,
            sn_value=c.Tests.ATTR_VALUE_TEST,
            attr_enabled=c.Tests.ATTR_ORCL_IS_ENABLED,
            attr_locked=c.Tests.ATTR_ORCL_ACCOUNT_LOCKED,
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
        if target_server == c.Tests.RFC:
            expected_true = c.Tests.BOOLEAN_OID_TO_RFC[input_true]
            expected_false = c.Tests.BOOLEAN_OID_TO_RFC[input_false]
        else:
            expected_true = c.Tests.BOOLEAN_RFC_TO_OID[input_true]
            expected_false = c.Tests.BOOLEAN_RFC_TO_OID[input_false]
        tm.that(
            content,
            has=f"{c.Tests.ATTR_ORCL_IS_ENABLED.lower()}: {expected_true}",
        )
        tm.that(
            content,
            has=f"{c.Tests.ATTR_ORCL_ACCOUNT_LOCKED.lower()}: {expected_false}",
        )
        tm.that(
            f"{c.Tests.ATTR_ORCL_IS_ENABLED.lower()}: {input_true}" not in content,
            eq=True,
        )
        tm.that(
            f"{c.Tests.ATTR_ORCL_ACCOUNT_LOCKED.lower()}: {input_false}" not in content,
            eq=True,
        )

    @pytest.mark.parametrize(
        ("source_server", "target_server", "input_attribute", "expected_attribute"),
        list(c.Tests.MIGRATION_ACL_CASES.values()),
        ids=list(c.Tests.MIGRATION_ACL_CASES.keys()),
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
        ldif_content = c.Tests.MIGRATION_ACL_ENTRY_TEMPLATE.format(
            dn=c.Tests.DN_TEST_USER,
            objectclass=c.Tests.NAME_OBJECTCLASS,
            top=c.Tests.NAME_TOP,
            person=c.Tests.NAME_PERSON,
            cn=c.Tests.NAME_CN,
            cn_value=c.Tests.ATTR_VALUE_TEST,
            sn=c.Tests.NAME_SN,
            sn_value=c.Tests.ATTR_VALUE_TEST,
            acl_attribute=input_attribute,
            acl_value=c.Tests.ACL_READ_VALUE,
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
            has=f"{expected_attribute}: {c.Tests.ACL_READ_VALUE}",
        )
        if expected_attribute == FlextLdifServersOidConstants.ORCLACI:
            _ = tm.that(
                not c.Tests.MIGRATION_ACI_LINE_REGEX.search(content),
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
        ldif_content = c.Tests.MIGRATION_SCHEMA_ENTRY_TEMPLATE.format(
            dn=FlextLdifServersOidConstants.SCHEMA_DN_SERVER,
            objectclass=c.Tests.NAME_OBJECTCLASS,
            top=c.Tests.NAME_TOP,
            subschema=c.Tests.NAME_SUBSCHEMA,
            cn=c.Tests.NAME_CN,
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
            f"dn: {FlextLdifServersOidConstants.SCHEMA_DN_SERVER}" not in content,
            eq=True,
        )

    def test_pipeline_enforces_servers(self, tmp_path: Path) -> None:
        """Test that pipeline enforces servers even if input looks like c.Tests.RFC."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        ldif_content = (
            f"dn: {c.Tests.DN_TEST_USER}\n"
            f"{c.Tests.NAME_OBJECTCLASS}: {c.Tests.NAME_TOP}\n"
            f"{c.Tests.NAME_OBJECTCLASS}: {c.Tests.NAME_PERSON}\n"
            f"{c.Tests.NAME_CN}: {c.Tests.ATTR_VALUE_TEST}\n"
            f"{c.Tests.ATTR_ORCL_IS_ENABLED}: {c.Tests.BOOLEAN_TRUE}\n"
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
        val_true_oid = c.Tests.BOOLEAN_RFC_TO_OID[c.Tests.BOOLEAN_TRUE]
        tm.that(
            content,
            has=f"{c.Tests.ATTR_ORCL_IS_ENABLED.lower()}: {val_true_oid}",
        )
