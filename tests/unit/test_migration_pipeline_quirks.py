"""Tests for migration pipeline server-specific quirks.

This module tests the FlextLdifMigrationPipeline with server-specific quirk
handling, validating server-to-server transformations including boolean value
conversions and other server-specific attribute transformations during migrations.
"""

from __future__ import annotations

import re
from pathlib import Path

from flext_tests.utilities import FlextTestsUtilities

from flext_ldif import FlextLdifConstants, FlextLdifMigrationPipeline
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc
from tests import c, s

# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)


class TestsFlextLdifMigrationPipelineQuirks(s):
    """Test suite for migration pipeline quirks."""

    def test_oid_boolean_conversion_oid_to_rfc(self, tmp_path: Path) -> None:
        """Test OID boolean conversion (0/1 -> TRUE/FALSE) during OID -> RFC migration."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create OID LDIF with boolean attributes
        # Use constants for attribute names and values
        attr_enabled = "orclIsEnabled"
        attr_locked = "orclAccountLocked"
        val_true_oid = OidTestConstants.RFC_TO_OID_BOOLEAN["TRUE"]
        val_false_oid = OidTestConstants.RFC_TO_OID_BOOLEAN["FALSE"]

        ldif_content = f"""dn: {c.DNs.TEST_USER}
{c.Names.OBJECTCLASS}: {c.Names.TOP}
{c.Names.OBJECTCLASS}: {c.Names.PERSON}
{c.Names.OBJECTCLASS}: orcluser
{c.Names.CN}: test
{c.Names.SN}: test
{attr_enabled}: {val_true_oid}
{attr_locked}: {val_false_oid}
"""
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=FlextLdifConstants.ServerTypes.OID,
            target_server=FlextLdifConstants.ServerTypes.RFC,
        )

        result = pipeline.execute()
        self.assert_success(result)

        # Verify output file content
        output_file = output_dir / "migrated.ldif"

        FlextTestsUtilities.FileHelpers.assert_file_exists(output_file)
        content = output_file.read_text(encoding="utf-8")

        # Should be converted to RFC format
        val_true_rfc = OidTestConstants.OID_TO_RFC_BOOLEAN[val_true_oid]
        val_false_rfc = OidTestConstants.OID_TO_RFC_BOOLEAN[val_false_oid]

        assert f"{attr_enabled}: {val_true_rfc}" in content
        assert f"{attr_locked}: {val_false_rfc}" in content
        assert f"{attr_enabled}: {val_true_oid}" not in content
        assert f"{attr_locked}: {val_false_oid}" not in content

    def test_oid_boolean_conversion_rfc_to_oid(self, tmp_path: Path) -> None:
        """Test OID boolean conversion (TRUE/FALSE -> 0/1) during RFC -> OID migration."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create RFC LDIF with boolean attributes
        attr_enabled = "orclIsEnabled"
        attr_locked = "orclAccountLocked"
        val_true_rfc = "TRUE"
        val_false_rfc = "FALSE"

        ldif_content = f"""dn: {c.DNs.TEST_USER}
{c.Names.OBJECTCLASS}: {c.Names.TOP}
{c.Names.OBJECTCLASS}: {c.Names.PERSON}
{c.Names.OBJECTCLASS}: orcluser
{c.Names.CN}: test
{c.Names.SN}: test
{attr_enabled}: {val_true_rfc}
{attr_locked}: {val_false_rfc}
"""
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=FlextLdifConstants.ServerTypes.RFC,
            target_server=FlextLdifConstants.ServerTypes.OID,
        )

        result = pipeline.execute()
        self.assert_success(result)

        # Verify output file content
        output_file = output_dir / "migrated.ldif"

        FlextTestsUtilities.FileHelpers.assert_file_exists(output_file)
        content = output_file.read_text(encoding="utf-8")

        # Should be converted to OID format
        val_true_oid = OidTestConstants.RFC_TO_OID_BOOLEAN[val_true_rfc]
        val_false_oid = OidTestConstants.RFC_TO_OID_BOOLEAN[val_false_rfc]

        assert f"{attr_enabled}: {val_true_oid}" in content
        assert f"{attr_locked}: {val_false_oid}" in content
        assert f"{attr_enabled}: {val_true_rfc}" not in content
        assert f"{attr_locked}: {val_false_rfc}" not in content

    def test_oid_acl_conversion_oid_to_rfc(self, tmp_path: Path) -> None:
        """Test OID ACL conversion (orclaci -> aci) during OID -> RFC migration."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create OID LDIF with orclaci
        acl_val = "access to entry by * (read)"
        ldif_content = f"""dn: {c.DNs.TEST_USER}
{c.Names.OBJECTCLASS}: {c.Names.TOP}
{c.Names.OBJECTCLASS}: {c.Names.PERSON}
{c.Names.CN}: test
{c.Names.SN}: test
{FlextLdifServersOidConstants.ORCLACI}: {acl_val}
"""
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=FlextLdifConstants.ServerTypes.OID,
            target_server=FlextLdifConstants.ServerTypes.RFC,
        )

        result = pipeline.execute()
        self.assert_success(result)

        # Verify output file content
        output_file = output_dir / "migrated.ldif"

        FlextTestsUtilities.FileHelpers.assert_file_exists(output_file)
        content = output_file.read_text(encoding="utf-8")

        # Should be converted to RFC format (aci)
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

        # Create RFC LDIF with aci
        acl_val = "access to entry by * (read)"
        ldif_content = f"""dn: {c.DNs.TEST_USER}
{c.Names.OBJECTCLASS}: {c.Names.TOP}
{c.Names.OBJECTCLASS}: {c.Names.PERSON}
{c.Names.CN}: test
{c.Names.SN}: test
{FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME}: {acl_val}
"""
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=FlextLdifConstants.ServerTypes.RFC,
            target_server=FlextLdifConstants.ServerTypes.OID,
        )

        result = pipeline.execute()
        self.assert_success(result)

        # Verify output file content
        output_file = output_dir / "migrated.ldif"

        FlextTestsUtilities.FileHelpers.assert_file_exists(output_file)
        content = output_file.read_text(encoding="utf-8")

        # Should be converted to OID format (orclaci)
        assert f"{FlextLdifServersOidConstants.ORCLACI}: {acl_val}" in content
        # Check that standalone 'aci:' is not present (use line-start pattern)
        # Note: 'orclaci:' contains 'aci:', so we check for '\naci:' or start-of-content
        assert not re.search(r"(^|\n)aci:", content), (
            "Should not have standalone 'aci:' attribute"
        )

    def test_oid_schema_dn_conversion(self, tmp_path: Path) -> None:
        """Test OID schema DN conversion (cn=subschemasubentry -> cn=schema)."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create OID LDIF with schema DN
        ldif_content = f"""dn: {FlextLdifServersOidConstants.SCHEMA_DN_QUIRK}
{c.Names.OBJECTCLASS}: {c.Names.TOP}
{c.Names.OBJECTCLASS}: subschema
{c.Names.CN}: subschemasubentry
"""
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=FlextLdifConstants.ServerTypes.OID,
            target_server=FlextLdifConstants.ServerTypes.RFC,
        )

        result = pipeline.execute()
        self.assert_success(result)

        # Verify output file content
        output_file = output_dir / "migrated.ldif"

        FlextTestsUtilities.FileHelpers.assert_file_exists(output_file)
        content = output_file.read_text(encoding="utf-8")

        # Should be converted to RFC format (cn=schema)
        assert f"dn: {FlextLdifServersRfc.Constants.SCHEMA_DN}" in content
        assert f"dn: {FlextLdifServersOidConstants.SCHEMA_DN_QUIRK}" not in content

    def test_pipeline_enforces_quirks(self, tmp_path: Path) -> None:
        """Test that pipeline enforces quirks even if input looks like c.RFC."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Input that looks like RFC (TRUE/FALSE) but we say it's OID
        attr_enabled = "orclIsEnabled"
        val_true_rfc = "TRUE"

        ldif_content = f"""dn: {c.DNs.TEST_USER}
{c.Names.OBJECTCLASS}: {c.Names.TOP}
{c.Names.OBJECTCLASS}: {c.Names.PERSON}
{c.Names.CN}: test
{attr_enabled}: {val_true_rfc}
"""
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")

        # Round trip: OID -> RFC -> OID
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server=FlextLdifConstants.ServerTypes.RFC,  # Treat input as RFC to parse "TRUE" correctly
            target_server=FlextLdifConstants.ServerTypes.OID,  # Target OID to enforce "1"
        )

        result = pipeline.execute()
        self.assert_success(result)

        output_file = output_dir / "migrated.ldif"
        content = output_file.read_text(encoding="utf-8")

        # Writer must output "1" for OID, even if input was "TRUE"
        val_true_oid = OidTestConstants.RFC_TO_OID_BOOLEAN[val_true_rfc]
        assert f"{attr_enabled}: {val_true_oid}" in content
