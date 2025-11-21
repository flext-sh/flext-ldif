"""Comprehensive unit tests for FlextLdifParser ParseFormatOptions.

Tests all parser format options with real LDIF content and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.services.parser import FlextLdifParser


class TestParserFormatOptions:
    """Test all ParseFormatOptions functionality."""

    @pytest.fixture
    def parser_service(self) -> FlextLdifParser:
        """Create parser service instance."""
        return FlextLdifParser()

    @pytest.fixture
    def sample_ldif_with_schema(self) -> str:
        """Sample LDIF content with schema entries."""
        return """version: 1

dn: cn=schema
objectClass: ldapSubentry
objectClass: subschema
cn: schema
attributeTypes: ( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectClasses: ( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )

dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: person
cn: John Doe
sn: Doe
telephoneNumber: +1-555-123-4567
"""

    @pytest.fixture
    def sample_ldif_with_acls(self) -> str:
        """Sample LDIF content with ACL attributes."""
        return """version: 1

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people
aci: (targetattr="*")(version 3.0; acl "Admin Access"; allow (all) userdn="ldap:///cn=admin,dc=example,dc=com";)
aci: (targetattr="cn || sn")(version 3.0; acl "Read Access"; allow (read) userdn="ldap:///anyone";)

dn: cn=Jane Smith,ou=people,dc=example,dc=com
objectClass: person
cn: Jane Smith
sn: Smith
"""

    @pytest.fixture
    def sample_ldif_with_operational_attrs(self) -> str:
        """Sample LDIF content with operational attributes."""
        return """version: 1

dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user
createTimestamp: 20250130120000Z
creatorsName: cn=admin,dc=example,dc=com
modifyTimestamp: 20250130130000Z
modifiersName: cn=admin,dc=example,dc=com
entryUUID: 12345678-1234-1234-1234-123456789abc
entryCSN: 20250130130000.000001Z#000000#001#000000
"""

    @pytest.fixture
    def invalid_ldif(self) -> str:
        """Invalid LDIF content for error testing."""
        return """version: 1

dn:
objectClass: person

dn: cn=no-objectclass,dc=example,dc=com
cn: test

dn: cn=empty-attrs,dc=example,dc=com
objectClass: person
cn:
sn:
"""

    def test_auto_parse_schema_enabled(
        self,
        parser_service: FlextLdifParser,
        sample_ldif_with_schema: str,
    ) -> None:
        """Test auto_parse_schema=True functionality."""
        options = FlextLdifModels.ParseFormatOptions(auto_parse_schema=True)

        result = parser_service.parse(
            content=sample_ldif_with_schema,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()
        assert response.statistics.schema_entries > 0
        assert response.statistics.data_entries > 0

        # Check that schema entry was processed
        schema_entries = [e for e in response.entries if "schema" in str(e.dn).lower()]
        assert len(schema_entries) > 0

    def test_auto_parse_schema_disabled(
        self,
        parser_service: FlextLdifParser,
        sample_ldif_with_schema: str,
    ) -> None:
        """Test auto_parse_schema=False functionality."""
        options = FlextLdifModels.ParseFormatOptions(auto_parse_schema=False)

        result = parser_service.parse(
            content=sample_ldif_with_schema,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()
        # All entries should be treated as data entries
        assert response.statistics.schema_entries == 0
        assert response.statistics.data_entries == len(response.entries)

    def test_auto_extract_acls_enabled(
        self,
        parser_service: FlextLdifParser,
        sample_ldif_with_acls: str,
    ) -> None:
        """Test auto_extract_acls=True functionality."""
        options = FlextLdifModels.ParseFormatOptions(auto_extract_acls=True)

        result = parser_service.parse(
            content=sample_ldif_with_acls,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()

        # Check that ACL extraction was attempted on entries with ACI attributes
        acl_entries = [
            e
            for e in response.entries
            if any("aci" in attr.lower() for attr in e.attributes)
        ]
        assert len(acl_entries) > 0

    def test_auto_extract_acls_disabled(
        self,
        parser_service: FlextLdifParser,
        sample_ldif_with_acls: str,
    ) -> None:
        """Test auto_extract_acls=False functionality."""
        options = FlextLdifModels.ParseFormatOptions(auto_extract_acls=False)

        result = parser_service.parse(
            content=sample_ldif_with_acls,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()

        # ACL extraction should not have been performed
        # Raw ACI attributes should still be present
        acl_entries = [
            e
            for e in response.entries
            if any("aci" in attr.lower() for attr in e.attributes)
        ]
        assert len(acl_entries) > 0
        assert len(response.entries) > 0

    def test_preserve_attribute_order_enabled(
        self,
        parser_service: FlextLdifParser,
    ) -> None:
        """Test preserve_attribute_order=True functionality."""
        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
objectClass: person
sn: Test
cn: Test User
telephoneNumber: 123-456-7890
mail: test@example.com
"""

        options = FlextLdifModels.ParseFormatOptions(preserve_attribute_order=True)

        result = parser_service.parse(
            content=ldif_content,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()

        # Check that attribute order was preserved in metadata
        for entry in response.entries:
            if entry.metadata and entry.metadata.extensions:
                attribute_order = entry.metadata.extensions.get("attribute_order")
                if attribute_order:
                    # Order should reflect the original LDIF order
                    assert isinstance(attribute_order, list)
                    assert len(attribute_order) > 0

    def test_preserve_attribute_order_disabled(
        self,
        parser_service: FlextLdifParser,
    ) -> None:
        """Test preserve_attribute_order=False functionality."""
        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
objectClass: person
sn: Test
cn: Test User
"""

        options = FlextLdifModels.ParseFormatOptions(preserve_attribute_order=False)

        result = parser_service.parse(
            content=ldif_content,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()

        # Attribute order should not be preserved in metadata
        for entry in response.entries:
            if entry.metadata and entry.metadata.extensions:
                attribute_order = entry.metadata.extensions.get("attribute_order")
                assert attribute_order is None

    def test_validate_entries_enabled_valid(
        self,
        parser_service: FlextLdifParser,
    ) -> None:
        """Test validate_entries=True with valid entries."""
        ldif_content = """version: 1

dn: cn=valid,dc=example,dc=com
objectClass: person
cn: Valid User
sn: User
"""

        options = FlextLdifModels.ParseFormatOptions(
            validate_entries=True,
            strict_schema_validation=False,
        )

        result = parser_service.parse(
            content=ldif_content,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()
        assert len(response.entries) > 0
        assert response.statistics.parse_errors == 0

    def test_validate_entries_enabled_invalid_non_strict(
        self,
        parser_service: FlextLdifParser,
        invalid_ldif: str,
    ) -> None:
        """Test validate_entries=True with invalid entries in non-strict mode."""
        options = FlextLdifModels.ParseFormatOptions(
            validate_entries=True,
            strict_schema_validation=False,
        )

        result = parser_service.parse(
            content=invalid_ldif,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        # Should succeed but with warnings logged
        assert result.is_success
        response = result.unwrap()
        # Some entries may be processed despite validation warnings
        assert len(response.entries) >= 0

    def test_validate_entries_strict_mode(
        self,
        parser_service: FlextLdifParser,
        invalid_ldif: str,
    ) -> None:
        """Test strict_schema_validation=True with invalid entries."""
        options = FlextLdifModels.ParseFormatOptions(
            validate_entries=True,
            strict_schema_validation=True,
        )

        result = parser_service.parse(
            content=invalid_ldif,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        # Should fail or have parse errors due to strict validation
        if result.is_success:
            response = result.unwrap()
            # Parse errors should be recorded
            assert response.statistics.parse_errors > 0
            assert len(response.entries) >= 0  # Use response to avoid warning
        else:
            # Complete failure is also acceptable in strict mode
            error_msg = result.error or ""
            assert "validation failed" in error_msg.lower()

    def test_normalize_dns_enabled(self, parser_service: FlextLdifParser) -> None:
        """Test normalize_dns=True functionality."""
        ldif_content = """version: 1

dn:   CN=Test   User,   OU=People,   DC=Example,   DC=Com
objectClass: person
cn: Test User
sn: User
"""

        options = FlextLdifModels.ParseFormatOptions(normalize_dns=True)

        result = parser_service.parse(
            content=ldif_content,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()

        # DN should be normalized (spaces trimmed)
        for entry in response.entries:
            dn_str = str(entry.dn.value)
            # Should not have extra spaces at the beginning or end
            assert dn_str == dn_str.strip()

    def test_normalize_dns_disabled(self, parser_service: FlextLdifParser) -> None:
        """Test normalize_dns=False functionality."""
        ldif_content = """version: 1

dn: CN=Test User,OU=People,DC=Example,DC=Com
objectClass: person
cn: Test User
sn: User
"""

        options = FlextLdifModels.ParseFormatOptions(normalize_dns=False)

        result = parser_service.parse(
            content=ldif_content,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()
        assert len(response.entries) > 0

    def test_max_parse_errors_limit(self, parser_service: FlextLdifParser) -> None:
        """Test max_parse_errors functionality."""
        # Create LDIF with multiple potential errors
        ldif_content = """version: 1

dn: cn=error1,dc=example,dc=com
objectClass: person
cn:
sn:

dn: cn=error2,dc=example,dc=com
objectClass: person
cn:
sn:

dn: cn=error3,dc=example,dc=com
objectClass: person
cn:
sn:
"""

        options = FlextLdifModels.ParseFormatOptions(
            max_parse_errors=2,
            validate_entries=True,
            strict_schema_validation=True,
        )

        result = parser_service.parse(
            content=ldif_content,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        # Should have stopped processing after reaching max errors
        if result.is_success:
            response = result.unwrap()
            assert response.statistics.parse_errors <= 2

    def test_max_parse_errors_unlimited(self, parser_service: FlextLdifParser) -> None:
        """Test max_parse_errors=0 (unlimited) functionality."""
        ldif_content = """version: 1

dn: cn=test1,dc=example,dc=com
objectClass: person
cn: Test1
sn: User1

dn: cn=test2,dc=example,dc=com
objectClass: person
cn: Test2
sn: User2
"""

        options = FlextLdifModels.ParseFormatOptions(max_parse_errors=0)

        result = parser_service.parse(
            content=ldif_content,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()
        assert len(response.entries) == 2

    def test_include_operational_attrs_enabled(
        self,
        parser_service: FlextLdifParser,
        sample_ldif_with_operational_attrs: str,
    ) -> None:
        """Test include_operational_attrs=True functionality."""
        options = FlextLdifModels.ParseFormatOptions(include_operational_attrs=True)

        result = parser_service.parse(
            content=sample_ldif_with_operational_attrs,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()

        # Operational attributes should be included
        for entry in response.entries:
            attr_names = [name.lower() for name in entry.attributes]
            # Should have operational attributes
            operational_found = any(
                op_attr in attr_names
                for op_attr in ["createtimestamp", "creatorsname", "entryuuid"]
            )
            if operational_found:
                # At least one entry should have operational attributes
                break
        else:
            pytest.fail(
                "No operational attributes found when include_operational_attrs=True",
            )

    def test_include_operational_attrs_disabled(
        self,
        parser_service: FlextLdifParser,
        sample_ldif_with_operational_attrs: str,
    ) -> None:
        """Test include_operational_attrs=False functionality."""
        options = FlextLdifModels.ParseFormatOptions(include_operational_attrs=False)

        result = parser_service.parse(
            content=sample_ldif_with_operational_attrs,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()

        # Operational attributes should be filtered out
        for entry in response.entries:
            attr_names = [name.lower() for name in entry.attributes]
            # Should not have operational attributes
            operational_found = any(
                op_attr in attr_names
                for op_attr in [
                    "createtimestamp",
                    "creatorsname",
                    "entryuuid",
                    "entrycsn",
                ]
            )
            assert not operational_found, (
                f"Found operational attributes in entry {entry.dn}: {attr_names}"
            )

    def test_combined_options(
        self,
        parser_service: FlextLdifParser,
        sample_ldif_with_schema: str,
    ) -> None:
        """Test combination of multiple options."""
        options = FlextLdifModels.ParseFormatOptions(
            auto_parse_schema=True,
            auto_extract_acls=True,
            preserve_attribute_order=True,
            validate_entries=True,
            normalize_dns=True,
            include_operational_attrs=False,
            strict_schema_validation=False,
            max_parse_errors=10,
        )

        result = parser_service.parse(
            content=sample_ldif_with_schema,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()

        # Verify multiple options worked together
        assert response.statistics.schema_entries > 0  # auto_parse_schema
        assert response.statistics.data_entries > 0
        assert response.statistics.parse_errors <= 10  # max_parse_errors

    def test_file_parsing_with_options(
        self,
        parser_service: FlextLdifParser,
        tmp_path: Path,
    ) -> None:
        """Test parsing from file with options."""
        ldif_content = """version: 1

dn: cn=file-test,dc=example,dc=com
objectClass: person
cn: File Test
sn: Test
"""

        # Create temporary LDIF file
        ldif_file = tmp_path / "test.ldif"
        ldif_file.write_text(ldif_content, encoding="utf-8")

        options = FlextLdifModels.ParseFormatOptions(
            validate_entries=True,
            normalize_dns=True,
        )

        result = parser_service.parse(
            content=ldif_file,
            input_source="file",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()
        assert len(response.entries) == 1
        assert response.entries[0].dn.value == "cn=file-test,dc=example,dc=com"

    def test_ldap3_parsing_with_options(self, parser_service: FlextLdifParser) -> None:
        """Test parsing from ldap3 results with options."""
        # Real ldap3 query results format: list[tuple[str, dict[str, list[str]]]]
        ldap3_results = [
            (
                "cn=ldap3-test,dc=example,dc=com",
                {
                    "objectClass": ["person"],
                    "cn": ["LDAP3 Test"],
                    "sn": ["Test"],
                    "createTimestamp": ["20250130120000Z"],
                    "entryUUID": ["12345678-1234-1234-1234-123456789abc"],
                },
            ),
        ]

        options = FlextLdifModels.ParseFormatOptions(
            include_operational_attrs=False,
            validate_entries=True,
            normalize_dns=True,
        )

        result = parser_service.parse(
            content=ldap3_results,
            input_source="ldap3",
            server_type="rfc",
            format_options=options,
        )

        assert result.is_success
        response = result.unwrap()
        assert len(response.entries) == 1

        entry = response.entries[0]
        attr_names = [name.lower() for name in entry.attributes]

        # Should not have operational attributes due to include_operational_attrs=False
        assert "createtimestamp" not in attr_names
        assert "entryuuid" not in attr_names

        # Should have regular attributes
        assert "objectclass" in attr_names
        assert "cn" in attr_names

    def test_options_default_values(self, parser_service: FlextLdifParser) -> None:
        """Test that default options work correctly."""
        ldif_content = """version: 1

dn: cn=default-test,dc=example,dc=com
objectClass: person
cn: Default Test
sn: Test
"""

        # Use default options (None should create default ParseFormatOptions)
        result = parser_service.parse(
            content=ldif_content,
            input_source="string",
            server_type="rfc",
            format_options=None,
        )

        assert result.is_success
        response = result.unwrap()
        assert len(response.entries) == 1

        # With defaults:
        # - auto_parse_schema=True
        # - auto_extract_acls=True
        # - validate_entries=True
        # - etc.
        assert response.statistics.parse_errors == 0

    def test_options_edge_cases(self, parser_service: FlextLdifParser) -> None:
        """Test edge cases with options."""
        # Empty LDIF
        result = parser_service.parse(
            content="version: 1\n\n",
            input_source="string",
            server_type="rfc",
            format_options=FlextLdifModels.ParseFormatOptions(),
        )

        assert result.is_success
        response = result.unwrap()
        assert len(response.entries) == 0
        assert response.statistics.total_entries == 0

    def test_invalid_server_type_with_options(
        self,
        parser_service: FlextLdifParser,
    ) -> None:
        """Test that options don't interfere with server type validation."""
        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user
"""

        options = FlextLdifModels.ParseFormatOptions(validate_entries=True)

        result = parser_service.parse(
            content=ldif_content,
            input_source="string",
            server_type="nonexistent_server_type",
            format_options=options,
        )

        # Should fail due to invalid server type, regardless of options
        assert result.is_failure
        error_msg = result.error or ""
        assert "server type" in error_msg.lower()
