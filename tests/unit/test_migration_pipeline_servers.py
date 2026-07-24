"""Behavioral tests for the migration pipeline server-to-server contract.

Exercises the PUBLIC contract of ``FlextLdifMigrationPipeline.execute`` only:
the ``r[T]`` outcome, the public fields of the returned
``MigrationPipelineResult`` model, and the observable content of the produced
output file. No private attributes, internal collaborators, or line-coverage
pokes are touched.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from tests import c

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifMigrationPipelineServers:
    """Behavioral suite for server-to-server migration via the public pipeline."""

    @staticmethod
    def _run_migration(
        *, tmp_path: Path, ldif_content: str, source_server: str, target_server: str
    ) -> tuple[str, int, tuple[str, ...]]:
        """Drive ``execute`` through its public API and return observable state.

        Returns the produced output-file text, the model's ``entry_count`` and
        its ``output_files`` tuple -- all public contract surface.
        """
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "test.ldif").write_text(ldif_content, encoding="utf-8")

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes(source_server),
            target_server=c.Ldif.ServerTypes(target_server),
        )
        migrated = tm.ok(pipeline.execute())

        output_file = output_dir / "migrated.ldif"
        _ = tm.that(output_file.exists(), eq=True)
        return (
            output_file.read_text(encoding="utf-8"),
            migrated.entry_count,
            tuple(migrated.output_files),
        )

    @pytest.mark.parametrize(
        ("source_server", "target_server", "input_true", "input_false"),
        list(c.Tests.MIGRATION_BOOLEAN_CASES.values()),
        ids=list(c.Tests.MIGRATION_BOOLEAN_CASES.keys()),
    )
    def test_boolean_values_are_converted_to_target_server_form(
        self,
        tmp_path: Path,
        source_server: str,
        target_server: str,
        input_true: str,
        input_false: str,
    ) -> None:
        """Boolean attribute values are rewritten to the target server's form."""
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
        content, entry_count, output_files = self._run_migration(
            tmp_path=tmp_path,
            ldif_content=ldif_content,
            source_server=source_server,
            target_server=target_server,
        )

        if target_server == c.Tests.RFC:
            expected_true = c.Tests.BOOLEAN_OID_TO_RFC[input_true]
            expected_false = c.Tests.BOOLEAN_OID_TO_RFC[input_false]
        else:
            expected_true = c.Tests.BOOLEAN_RFC_TO_OID[input_true]
            expected_false = c.Tests.BOOLEAN_RFC_TO_OID[input_false]

        enabled = c.Tests.ATTR_ORCL_IS_ENABLED.lower()
        locked = c.Tests.ATTR_ORCL_ACCOUNT_LOCKED.lower()

        # Public model state: the single input entry survived the migration and
        # the pipeline reported the produced output artifact.
        tm.that(entry_count, eq=1)
        tm.that(len(output_files), eq=1)

        # Observable output: target-form values present, source-form absent.
        tm.that(content, has=f"{enabled}: {expected_true}")
        tm.that(content, has=f"{locked}: {expected_false}")
        tm.that(f"{enabled}: {input_true}" not in content, eq=True)
        tm.that(f"{locked}: {input_false}" not in content, eq=True)

    @pytest.mark.parametrize(
        ("source_server", "target_server", "input_attribute", "expected_attribute"),
        list(c.Tests.MIGRATION_ACL_CASES.values()),
        ids=list(c.Tests.MIGRATION_ACL_CASES.keys()),
    )
    def test_acl_attribute_is_renamed_to_target_server_form(
        self,
        tmp_path: Path,
        source_server: str,
        target_server: str,
        input_attribute: str,
        expected_attribute: str,
    ) -> None:
        """ACL attribute names are rewritten to the target server's convention."""
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
        content, entry_count, output_files = self._run_migration(
            tmp_path=tmp_path,
            ldif_content=ldif_content,
            source_server=source_server,
            target_server=target_server,
        )

        tm.that(entry_count, eq=1)
        tm.that(len(output_files), eq=1)
        tm.that(content, has=f"{expected_attribute}: {c.Tests.ACL_READ_VALUE}")

        if expected_attribute == FlextLdifServersOidConstants.ORCLACI:
            _ = tm.that(not c.Tests.MIGRATION_ACI_LINE_REGEX.search(content), eq=True)
        else:
            tm.that(f"{FlextLdifServersOidConstants.ORCLACI}:" not in content, eq=True)

    def test_schema_dn_is_converted_from_oid_to_rfc(self, tmp_path: Path) -> None:
        """OID schema DN (cn=subschemasubentry) is rewritten to the RFC schema DN."""
        ldif_content = c.Tests.MIGRATION_SCHEMA_ENTRY_TEMPLATE.format(
            dn=FlextLdifServersOidConstants.SCHEMA_DN_SERVER,
            objectclass=c.Tests.NAME_OBJECTCLASS,
            top=c.Tests.NAME_TOP,
            subschema=c.Tests.NAME_SUBSCHEMA,
            cn=c.Tests.NAME_CN,
        )
        content, _entry_count, _output_files = self._run_migration(
            tmp_path=tmp_path,
            ldif_content=ldif_content,
            source_server=c.Ldif.ServerTypes.OID,
            target_server=c.Ldif.ServerTypes.RFC,
        )

        tm.that(content, has=f"dn: {FlextLdifServersRfc.Constants.SCHEMA_DN}")
        tm.that(
            f"dn: {FlextLdifServersOidConstants.SCHEMA_DN_SERVER}" not in content,
            eq=True,
        )

    def test_target_server_form_is_enforced_regardless_of_input_shape(
        self, tmp_path: Path
    ) -> None:
        """The pipeline converts to the target server form even for RFC-shaped input."""
        ldif_content = (
            f"dn: {c.Tests.DN_TEST_USER}\n"
            f"{c.Tests.NAME_OBJECTCLASS}: {c.Tests.NAME_TOP}\n"
            f"{c.Tests.NAME_OBJECTCLASS}: {c.Tests.NAME_PERSON}\n"
            f"{c.Tests.NAME_CN}: {c.Tests.ATTR_VALUE_TEST}\n"
            f"{c.Tests.ATTR_ORCL_IS_ENABLED}: {c.Tests.BOOLEAN_TRUE}\n"
        )
        content, entry_count, _output_files = self._run_migration(
            tmp_path=tmp_path,
            ldif_content=ldif_content,
            source_server=c.Ldif.ServerTypes.RFC,
            target_server=c.Ldif.ServerTypes.OID,
        )

        val_true_oid = c.Tests.BOOLEAN_RFC_TO_OID[c.Tests.BOOLEAN_TRUE]
        tm.that(entry_count, eq=1)
        tm.that(content, has=f"{c.Tests.ATTR_ORCL_IS_ENABLED.lower()}: {val_true_oid}")

    def test_execute_fails_when_input_directory_is_missing(
        self, tmp_path: Path
    ) -> None:
        """execute() surfaces a typed failure r[T] when input_dir does not exist."""
        missing_input = tmp_path / "does_not_exist"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=missing_input,
            output_dir=output_dir,
            output_filename="migrated.ldif",
            source_server=c.Ldif.ServerTypes.OID,
            target_server=c.Ldif.ServerTypes.RFC,
        )
        result = pipeline.execute()

        tm.that(result.failure, eq=True)
        tm.that(str(missing_input) in (result.error or ""), eq=True)
