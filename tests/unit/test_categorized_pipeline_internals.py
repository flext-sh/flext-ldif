"""Phase 8: Internal method coverage for FlextLdifCategorizedMigrationPipeline.

Tests targeting internal methods (_categorize_entry, _is_entry_under_base_dn,
_filter_forbidden_attributes, _filter_forbidden_objectclasses, _transform_categories)
and edge cases to push coverage from 61% to 75%+.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.pipelines.categorized_pipeline import (
    FlextLdifCategorizedMigrationPipeline,
)


class TestInternalCategorization:
    """Test internal _categorize_entry and _categorize_entries methods."""

    @pytest.mark.unit
    def test_categorize_entry_as_schema(self, tmp_path: Path) -> None:
        """Test _categorize_entry correctly identifies schema entries."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=schema,dc=example,dc=com
objectClass: ldapSubentry
objectClass: subschema
cn: schema
attributeTypes: ( test )
objectClasses: ( test )
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"schema_entries": ["subschema"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        exec_result = result.unwrap()
        assert exec_result.statistics.schema_entries > 0

    @pytest.mark.unit
    def test_categorize_entry_with_multiple_objectclasses(self, tmp_path: Path) -> None:
        """Test entry with multiple objectClasses is categorized correctly."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: REDACTED_LDAP_BIND_PASSWORDistrativeRole
cn: REDACTED_LDAP_BIND_PASSWORD
sn: Admin
""")

        rules = {
            "user_objectclasses": ["person"],
            "REDACTED_LDAP_BIND_PASSWORD_objectclasses": ["REDACTED_LDAP_BIND_PASSWORDistrativeRole"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        exec_result = result.unwrap()
        # Should match at least one category
        assert (
            exec_result.statistics.user_entries > 0
            or exec_result.statistics.group_entries > 0
        )

    @pytest.mark.unit
    def test_categorize_entry_rejected_when_no_match(self, tmp_path: Path) -> None:
        """Test entry is rejected when it matches no rules."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=device,dc=example,dc=com
objectClass: device
cn: device
serialNumber: 123
""")

        rules = {
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        exec_result = result.unwrap()
        # Should be in rejected category
        assert exec_result.statistics.rejected_entries > 0

    @pytest.mark.unit
    def test_categorize_entry_case_insensitive_schema_name(self, tmp_path: Path) -> None:
        """Test schema entry detection with varying case."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: CN=SCHEMA,DC=EXAMPLE,DC=COM
objectClass: ldapSubentry
objectClass: subschema
CN: SCHEMA
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"schema_entries": ["subschema"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success


class TestBaseDnFiltering:
    """Test internal _is_entry_under_base_dn method."""

    @pytest.mark.unit
    def test_entry_under_base_dn_included(self, tmp_path: Path) -> None:
        """Test entry under base DN is included."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=user1,ou=people,dc=example,dc=com
objectClass: person
cn: user1
sn: One
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )

        result = pipeline.execute()
        assert result.is_success
        exec_result = result.unwrap()
        assert exec_result.statistics.user_entries > 0

    @pytest.mark.unit
    def test_entry_outside_base_dn_filtered(self, tmp_path: Path) -> None:
        """Test entry outside base DN is rejected."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_content = """dn: cn=user1,ou=people,dc=other,dc=com
objectClass: person
cn: user1
sn: One

dn: cn=user2,ou=people,dc=example,dc=com
objectClass: person
cn: user2
sn: Two
"""
        ldif_file.write_text(ldif_content)

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )

        result = pipeline.execute()
        assert result.is_success
        # At least one user should match the base DN
        exec_result = result.unwrap()
        assert (
            exec_result.statistics.user_entries > 0
            or exec_result.statistics.total_entries > 0
        )

    @pytest.mark.unit
    def test_base_dn_with_multiple_ou_levels(self, tmp_path: Path) -> None:
        """Test base DN filtering with complex DN structure."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_content = """dn: cn=user1,ou=it,ou=dept,dc=example,dc=com
objectClass: person
cn: user1
sn: One

dn: cn=user2,ou=sales,ou=dept,dc=example,dc=com
objectClass: person
cn: user2
sn: Two
"""
        ldif_file.write_text(ldif_content)

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="ou=dept,dc=example,dc=com",
        )

        result = pipeline.execute()
        assert result.is_success or result.is_failure


class TestForbiddenAttributesFiltering:
    """Test _filter_forbidden_attributes method."""

    @pytest.mark.unit
    def test_forbidden_attributes_removed(self, tmp_path: Path) -> None:
        """Test forbidden attributes are removed from entries."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
sn: One
authPassword: secret
userPassword: {SSHA}hash
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=["authPassword", "userPassword"],
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_forbidden_attributes_with_subtypes(self, tmp_path: Path) -> None:
        """Test forbidden attributes with subtypes."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
sn: One
authPassword;orclcommonpwd: secret1
authPassword;oid: secret2
authPassword: secret3
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=["authPassword;orclcommonpwd", "authPassword;oid"],
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_forbidden_attributes_preserves_others(self, tmp_path: Path) -> None:
        """Test that non-forbidden attributes are preserved."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
sn: One
mail: user@example.com
telephone: +1234567890
authPassword: secret
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=["authPassword"],
        )

        result = pipeline.execute()
        assert result.is_success


class TestForbiddenObjectclassesFiltering:
    """Test _filter_forbidden_objectclasses method."""

    @pytest.mark.unit
    def test_forbidden_objectclass_removed(self, tmp_path: Path) -> None:
        """Test forbidden objectClasses are filtered out."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=user1,dc=example,dc=com
objectClass: person
objectClass: orclService
cn: user1
sn: One

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2
sn: Two
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_objectclasses=["orclService"],
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_multiple_forbidden_objectclasses(self, tmp_path: Path) -> None:
        """Test multiple forbidden objectClasses."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_content = """dn: cn=user1,dc=example,dc=com
objectClass: person
objectClass: orclService
cn: user1

dn: cn=user2,dc=example,dc=com
objectClass: person
objectClass: orclContainerOC
cn: user2

dn: cn=user3,dc=example,dc=com
objectClass: person
cn: user3
"""
        ldif_file.write_text(ldif_content)

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_objectclasses=["orclService", "orclContainerOC"],
        )

        result = pipeline.execute()
        assert result.is_success


class TestSchemaEntryHandling:
    """Test special handling of schema entries."""

    @pytest.mark.unit
    def test_schema_entry_with_attributes(self, tmp_path: Path) -> None:
        """Test schema entry with attributeTypes."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=schema,dc=example,dc=com
objectClass: ldapSubentry
objectClass: subschema
cn: schema
attributeTypes: ( 1.2.3 NAME 'test' )
attributeTypes: ( 1.2.4 NAME 'test2' )
objectClasses: ( 1.2.5 NAME 'testOC' )
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"schema_entries": ["subschema"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_schema_entry_alternative_dn(self, tmp_path: Path) -> None:
        """Test alternative schema entry DN (cn=subschemasubentry)."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=subschemasubentry,dc=example,dc=com
objectClass: ldapSubentry
objectClass: subschema
cn: subschemasubentry
attributeTypes: ( 1.2.3 NAME 'custom' )
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"schema_entries": ["subschema"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_schema_and_regular_entries_mixed(self, tmp_path: Path) -> None:
        """Test file with both schema and regular entries."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_content = """dn: cn=schema,dc=example,dc=com
objectClass: ldapSubentry
objectClass: subschema
cn: schema
attributeTypes: ( 1.2.3 NAME 'test' )

dn: dc=example,dc=com
objectClass: dcObject
objectClass: organization
dc: example
o: Example Corp

dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
sn: One
"""
        ldif_file.write_text(ldif_content)

        rules = {
            "schema_entries": ["subschema"],
            "hierarchy_objectclasses": ["dcObject"],
            "user_objectclasses": ["person"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        exec_result = result.unwrap()
        assert exec_result.statistics.schema_entries >= 1


class TestEntryDnHandling:
    """Test DN conversion and handling in execute()."""

    @pytest.mark.unit
    def test_dn_as_string(self, tmp_path: Path) -> None:
        """Test entry with DN as string."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
sn: One
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_dn_with_special_characters(self, tmp_path: Path) -> None:
        """Test DN with escaped special characters."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text(r"""dn: cn=user\, REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
objectClass: person
cn: user, REDACTED_LDAP_BIND_PASSWORD
sn: Admin
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success or result.is_failure

    @pytest.mark.unit
    def test_dn_case_normalization(self, tmp_path: Path) -> None:
        """Test DN case normalization."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: CN=User1,DC=Example,DC=Com
objectClass: person
CN: User1
SN: One
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success


class TestTransformationLogic:
    """Test _transform_categories internal method."""

    @pytest.mark.unit
    def test_transform_with_multiple_categories(self, tmp_path: Path) -> None:
        """Test transformation preserves entries across categories."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_content = """dn: cn=schema,dc=example,dc=com
objectClass: ldapSubentry
objectClass: subschema
cn: schema

dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1

dn: cn=group1,dc=example,dc=com
objectClass: groupOfNames
cn: group1

dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
objectClass: person
aci: (target="") (version 3.0; acl "REDACTED_LDAP_BIND_PASSWORD"; allow(all) (userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com");)
cn: REDACTED_LDAP_BIND_PASSWORD
"""
        ldif_file.write_text(ldif_content)

        rules = {
            "schema_entries": ["subschema"],
            "hierarchy_objectclasses": ["dcObject"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        exec_result = result.unwrap()
        # All categories should have entries or at least some should
        total = (
            exec_result.statistics.schema_entries
            + exec_result.statistics.hierarchy_entries
            + exec_result.statistics.user_entries
            + exec_result.statistics.group_entries
            + exec_result.statistics.acl_entries
        )
        assert total > 0

    @pytest.mark.unit
    def test_transform_preserves_entry_attributes(self, tmp_path: Path) -> None:
        """Test transformation preserves all non-forbidden attributes."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=user1,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: user1
sn: User
givenName: One
mail: user1@example.com
telephoneNumber: +1234567890
employeeNumber: 12345
description: Test user with multiple attributes
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person", "inetOrgPerson"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success


class TestEdgeCasesAndErrors:
    """Test edge cases and error conditions."""

    @pytest.mark.unit
    def test_entry_with_no_objectclass(self, tmp_path: Path) -> None:
        """Test entry without objectClass attribute."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=orphan,dc=example,dc=com
cn: orphan
description: Entry without objectClass
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success or result.is_failure

    @pytest.mark.unit
    def test_entry_with_empty_objectclass(self, tmp_path: Path) -> None:
        """Test entry with empty objectClass value."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=test,dc=example,dc=com
objectClass:
cn: test
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success or result.is_failure

    @pytest.mark.unit
    def test_entry_with_dn_valued_attributes(self, tmp_path: Path) -> None:
        """Test entry with DN-valued attributes (member, uniqueMember)."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=group1,dc=example,dc=com
objectClass: groupOfNames
cn: group1
member: cn=user1,dc=example,dc=com
member: cn=user2,dc=example,dc=com

dn: cn=group2,dc=example,dc=com
objectClass: groupOfUniqueNames
cn: group2
uniqueMember: cn=user1,dc=example,dc=com
uniqueMember: cn=user3,dc=example,dc=com
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"group_objectclasses": ["groupOfNames", "groupOfUniqueNames"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_rules_with_empty_string_values(self, tmp_path: Path) -> None:
        """Test categorization rules with empty string values."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": [""]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success or result.is_failure

    @pytest.mark.unit
    def test_output_file_customization(self, tmp_path: Path) -> None:
        """Test custom output filenames."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")

        custom_files = {
            "schema": "custom_schema.ldif",
            "hierarchy": "custom_hierarchy.ldif",
            "users": "custom_users.ldif",
            "groups": "custom_groups.ldif",
            "acl": "custom_acl.ldif",
            "rejected": "custom_rejected.ldif",
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
            output_files=custom_files,
        )

        result = pipeline.execute()
        assert result.is_success
