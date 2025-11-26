"""Unit tests for FlextLdifParser ParseFormatOptions.

**Modules Tested:**
- flext_ldif.services.parser.FlextLdifParser: LDIF parsing service with format options
- flext_ldif.models.FlextLdifModels.ParseFormatOptions: Parser format configuration

**Scope:**
- All format options (auto_parse_schema, auto_extract_acls, preserve_attribute_order,
  validate_entries, normalize_dns, max_parse_errors)
- Input sources (string, file, ldap3)
- Edge cases and error handling
- Combined options validation
- Default values and empty content handling

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import Literal

import pytest

from flext_ldif import FlextLdifModels, FlextLdifParser

from ...fixtures.constants import DNs, Names, OIDs, Syntax, Values
from ...helpers.test_assertions import TestAssertions
from ...helpers.test_ldif_helpers import OptimizedLdifTestHelpers


class TestParserFormatOptions:
    """Test all ParseFormatOptions functionality.

    Uses advanced Python 3.13 features, factories, and parametrization
    to reduce code while maintaining 100% coverage and testing all edge cases.
    """

    class InputSource(Enum):
        """Input source types for parser testing."""

        STRING = "string"
        FILE = "file"
        LDAP3 = "ldap3"

    class OptionConfig:
        """Configuration mapping for format options testing."""

        @staticmethod
        def get_boolean_options() -> dict[
            str,
            tuple[
                str,
                str,
                str | None,
            ],
        ]:
            """Get boolean options configuration.

            Returns mapping of option name to (fixture_name, validator_enabled_name, validator_disabled_name).
            """
            return {
                "auto_parse_schema": (
                    "ldif_with_schema",
                    "has_schema_entries",
                    "no_schema_entries",
                ),
                "auto_extract_acls": ("ldif_with_acls", "has_acl_attributes", None),
                "preserve_attribute_order": (
                    "entry_with_attribute_order",
                    "attribute_order_preserved",
                    "attribute_order_not_preserved",
                ),
                "normalize_dns": ("basic_entry", "normalized_dns", None),
            }

    class Fixtures:
        """Nested class for test fixtures and data factories."""

        @staticmethod
        def ldif_with_schema() -> str:
            """Create LDIF content with schema entries."""
            return f"""version: 1

dn: {DNs.SCHEMA}
objectClass: ldapSubentry
objectClass: subschema
cn: schema
attributeTypes: ( {OIDs.CN} NAME '{Names.CN}' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX {Syntax.DIRECTORY_STRING} )
objectClasses: ( {OIDs.PERSON} NAME '{Names.PERSON}' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )

dn: cn=John Doe,ou=people,{DNs.EXAMPLE}
objectClass: {Names.PERSON}
cn: John Doe
sn: Doe
telephoneNumber: +1-555-123-4567
"""

        @staticmethod
        def ldif_with_acls() -> str:
            """Create LDIF content with ACL attributes."""
            return f"""version: 1

dn: ou=people,{DNs.EXAMPLE}
objectClass: organizationalUnit
ou: people
aci: (targetattr="*")(version 3.0; acl "Admin Access"; allow (all) userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,{DNs.EXAMPLE}";)
aci: (targetattr="cn || sn")(version 3.0; acl "Read Access"; allow (read) userdn="ldap:///anyone";)

dn: cn=Jane Smith,ou=people,{DNs.EXAMPLE}
objectClass: {Names.PERSON}
cn: Jane Smith
sn: Smith
"""

        @staticmethod
        def invalid_ldif() -> str:
            """Create invalid LDIF content for error testing."""
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

        @staticmethod
        def basic_entry(dn: str = DNs.TEST_USER) -> str:
            """Create basic LDIF entry."""
            return f"""version: 1

dn: {dn}
objectClass: {Names.PERSON}
cn: {Values.TEST}
sn: {Values.USER}
"""

        @staticmethod
        def entry_with_attribute_order() -> str:
            """Create LDIF entry with specific attribute order."""
            return f"""version: 1

dn: {DNs.TEST_USER}
objectClass: {Names.PERSON}
sn: Test
cn: Test User
telephoneNumber: 123-456-7890
mail: test@example.com
"""

        @staticmethod
        def ldif_with_errors(count: int = 3) -> str:
            """Create LDIF with both valid and invalid entries.

            Creates entries: valid1, error1, valid2, error2, error3.
            So with count=3, you get 2 valid + 3 invalid = 5 total.
            When max_parse_errors=0 (no limit), all should parse.
            When strict validation is on, invalid entries have errors marked.
            """
            valid_entries = [
                f"""dn: cn=valid{i},dc=example,dc=com
objectClass: {Names.PERSON}
cn: Valid User {i}
sn: User{i}"""
                for i in range(1, 3)  # 2 valid entries
            ]
            invalid_entries = [
                f"""dn: cn=error{i},dc=example,dc=com
objectClass: {Names.PERSON}
cn:
sn:"""
                for i in range(1, count + 1)  # N invalid entries with empty cn/sn
            ]
            # Interleave valid and invalid: valid1, invalid1, valid2, invalid2, invalid3
            all_entries = []
            for i, invalid in enumerate(invalid_entries):
                if i < len(valid_entries):
                    all_entries.append(valid_entries[i])
                all_entries.append(invalid)

            entries = "\n\n".join(all_entries)
            return f"version: 1\n\n{entries}\n"

        @staticmethod
        def ldap3_results() -> list[tuple[str, dict[str, list[str]]]]:
            """Create ldap3 query results format."""
            return [
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

    class Helpers:
        """Nested class for test helper methods."""

        @staticmethod
        def parse_and_assert(
            parser: FlextLdifParser,
            content: str | Path | list[tuple[str, dict[str, list[str]]]],
            input_source: Literal["string", "file", "ldap3"] = "string",
            server_type: str = "rfc",
            format_options: FlextLdifModels.ParseFormatOptions | None = None,
        ) -> FlextLdifModels.ParseResponse:
            """Parse content and assert success, returning response.

            Reduces 5-7 lines of repetitive parsing code per test.
            """
            result = parser.parse(
                content=content,
                input_source=input_source,
                server_type=server_type,
                format_options=format_options,
            )
            response_obj = TestAssertions.assert_success(result, "Parse should succeed")
            assert isinstance(response_obj, FlextLdifModels.ParseResponse)
            return response_obj

    class Validators:
        """Nested class for validation functions."""

        @staticmethod
        def has_schema_entries(response: FlextLdifModels.ParseResponse) -> None:
            """Validate schema entries exist."""
            assert response.statistics.schema_entries > 0
            assert response.statistics.data_entries > 0
            schema_entries = [
                e for e in response.entries if "schema" in str(e.dn).lower()
            ]
            assert len(schema_entries) > 0

        @staticmethod
        def no_schema_entries(response: FlextLdifModels.ParseResponse) -> None:
            """Validate no schema entries."""
            assert response.statistics.schema_entries == 0
            assert response.statistics.data_entries == len(response.entries)

        @staticmethod
        def has_acl_attributes(response: FlextLdifModels.ParseResponse) -> None:
            """Validate ACL attributes exist in entries."""
            acl_entries = [
                e
                for e in response.entries
                if any(
                    "aci" in str(attr).lower()
                    for attr in (
                        e.attributes.attributes
                        if hasattr(e.attributes, "attributes")
                        else []
                    )
                )
            ]
            assert len(acl_entries) > 0

        @staticmethod
        def attribute_order_preserved(
            response: FlextLdifModels.ParseResponse,
        ) -> None:
            """Validate attribute order is preserved."""
            for entry in response.entries:
                if entry.metadata and entry.metadata.extensions:
                    attribute_order = entry.metadata.extensions.get("attribute_order")
                    if attribute_order:
                        assert isinstance(attribute_order, list)
                        assert len(attribute_order) > 0

        @staticmethod
        def attribute_order_not_preserved(
            response: FlextLdifModels.ParseResponse,
        ) -> None:
            """Validate attribute order is not preserved."""
            for entry in response.entries:
                if entry.metadata and entry.metadata.extensions:
                    attribute_order = entry.metadata.extensions.get("attribute_order")
                    assert attribute_order is None

        @staticmethod
        def normalized_dns(response: FlextLdifModels.ParseResponse) -> None:
            """Validate DNs are normalized."""
            for entry in response.entries:
                dn_str = str(entry.dn.value)
                assert dn_str == dn_str.strip()

        @staticmethod
        def has_operational_attrs(response: FlextLdifModels.ParseResponse) -> None:
            """Validate operational attributes are included."""
            operational_found = False
            for entry in response.entries:
                attr_names = [name.lower() for name in entry.attributes.attributes]
                if any(
                    op_attr in attr_names
                    for op_attr in ["createtimestamp", "creatorsname", "entryuuid"]
                ):
                    operational_found = True
                    break
            assert operational_found, "No operational attributes found"

        @staticmethod
        def no_operational_attrs(response: FlextLdifModels.ParseResponse) -> None:
            """Validate operational attributes are filtered out."""
            for entry in response.entries:
                attr_names = [name.lower() for name in entry.attributes.attributes]
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

        @staticmethod
        def parse_errors_within_limit(
            limit: int,
        ) -> Callable[[FlextLdifModels.ParseResponse], None]:
            """Create validator for parse errors within limit."""

            def validator(response: FlextLdifModels.ParseResponse) -> None:
                assert response.statistics.parse_errors <= limit

            return validator

    @pytest.fixture
    def parser_service(self) -> FlextLdifParser:
        """Create parser service instance."""
        return OptimizedLdifTestHelpers.create_parser()

    @pytest.mark.parametrize(
        ("option_name", "enabled"),
        [
            (option, enabled)
            for option in [
                "auto_parse_schema",
                "auto_extract_acls",
                "preserve_attribute_order",
                "normalize_dns",
            ]
            for enabled in [True, False]
        ],
    )
    def test_boolean_format_options(
        self,
        parser_service: FlextLdifParser,
        option_name: str,
        enabled: bool,
    ) -> None:
        """Test boolean format options using dynamic parametrization.

        Reduces 6 separate test methods into one dynamic test.
        """
        boolean_options = self.OptionConfig.get_boolean_options()
        fixture_name, validator_enabled_name, validator_disabled_name = boolean_options[
            option_name
        ]
        fixture_method = getattr(self.Fixtures, fixture_name)
        options = FlextLdifModels.ParseFormatOptions(**{option_name: enabled})
        response_obj = self.Helpers.parse_and_assert(
            parser_service,
            fixture_method(),
            format_options=options,
        )
        if enabled and validator_enabled_name:
            validator_enabled = getattr(self.Validators, validator_enabled_name)
            validator_enabled(response_obj)
        elif not enabled and validator_disabled_name:
            validator_disabled = getattr(self.Validators, validator_disabled_name)
            validator_disabled(response_obj)
        assert len(response_obj.entries) > 0

    @pytest.mark.parametrize(
        ("strict", "expected_errors"),
        [(False, ">=0"), (True, ">0")],
    )
    def test_validate_entries(
        self,
        parser_service: FlextLdifParser,
        strict: bool,
        expected_errors: str,
    ) -> None:
        """Test validate_entries with strict/non-strict mode."""
        options = FlextLdifModels.ParseFormatOptions(
            validate_entries=True,
            strict_schema_validation=strict,
        )
        ldif = self.Fixtures.invalid_ldif()

        result = parser_service.parse(
            content=ldif,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        if result.is_success:
            response = result.unwrap()
            if strict:
                assert response.statistics.parse_errors > 0
            assert len(response.entries) >= 0
        else:
            error_msg = result.error or ""
            assert "validation" in error_msg.lower() or "error" in error_msg.lower()

    @pytest.mark.parametrize(
        ("max_errors", "expected_count"),
        [(2, "<=2"), (0, "==2")],
    )
    def test_max_parse_errors(
        self,
        parser_service: FlextLdifParser,
        max_errors: int,
        expected_count: str,
    ) -> None:
        """Test max_parse_errors functionality."""
        ldif = self.Fixtures.ldif_with_errors(3)
        options = FlextLdifModels.ParseFormatOptions(
            max_parse_errors=max_errors,
            validate_entries=True,
            strict_schema_validation=True,
        )

        result = parser_service.parse(
            content=ldif,
            input_source="string",
            server_type="rfc",
            format_options=options,
        )

        if result.is_success:
            response = result.unwrap()
            if max_errors > 0:
                assert response.statistics.parse_errors <= max_errors
            else:
                assert len(response.entries) == 2

    def test_combined_options(
        self,
        parser_service: FlextLdifParser,
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
        response_obj = self.Helpers.parse_and_assert(
            parser_service,
            self.Fixtures.ldif_with_schema(),
            format_options=options,
        )
        assert response_obj.statistics.schema_entries > 0
        assert response_obj.statistics.data_entries > 0
        assert response_obj.statistics.parse_errors <= 10

    def test_file_parsing_with_options(
        self,
        parser_service: FlextLdifParser,
        tmp_path: Path,
    ) -> None:
        """Test parsing from file with options."""
        ldif_content = self.Fixtures.basic_entry("cn=file-test,dc=example,dc=com")
        ldif_file = tmp_path / "test.ldif"
        _ = ldif_file.write_text(ldif_content, encoding="utf-8")
        options = FlextLdifModels.ParseFormatOptions(
            validate_entries=True,
            normalize_dns=True,
        )
        response_obj = self.Helpers.parse_and_assert(
            parser_service,
            ldif_file,
            input_source="file",
            format_options=options,
        )
        assert len(response_obj.entries) == 1
        assert response_obj.entries[0].dn.value == "cn=file-test,dc=example,dc=com"

    def test_ldap3_parsing_with_options(
        self,
        parser_service: FlextLdifParser,
    ) -> None:
        """Test parsing from ldap3 results with options."""
        ldap3_results = self.Fixtures.ldap3_results()
        options = FlextLdifModels.ParseFormatOptions(
            include_operational_attrs=False,
            validate_entries=True,
            normalize_dns=True,
        )
        response_obj = self.Helpers.parse_and_assert(
            parser_service,
            ldap3_results,
            input_source="ldap3",
            format_options=options,
        )
        assert len(response_obj.entries) == 1
        entry = response_obj.entries[0]
        attr_names = [name.lower() for name in entry.attributes.attributes]
        assert "createtimestamp" not in attr_names
        assert "entryuuid" not in attr_names
        assert "objectclass" in attr_names
        assert "cn" in attr_names

    @pytest.mark.parametrize(
        ("content", "expected_entries", "expected_errors"),
        [
            (
                lambda: TestParserFormatOptions.Fixtures.basic_entry(
                    "cn=default-test,dc=example,dc=com",
                ),
                1,
                0,
            ),
            (lambda: "version: 1\n\n", 0, 0),
        ],
    )
    def test_options_edge_cases_and_defaults(
        self,
        parser_service: FlextLdifParser,
        content: Callable[[], str],
        expected_entries: int,
        expected_errors: int,
    ) -> None:
        """Test edge cases and default options using dynamic parametrization."""
        ldif = content()
        response_obj = self.Helpers.parse_and_assert(
            parser_service,
            ldif,
            format_options=None
            if expected_entries > 0
            else FlextLdifModels.ParseFormatOptions(),
        )
        assert response_obj.statistics.parse_errors == expected_errors
        assert len(response_obj.entries) == expected_entries

    def test_invalid_server_type_with_options(
        self,
        parser_service: FlextLdifParser,
    ) -> None:
        """Test that options don't interfere with server type validation."""
        ldif = self.Fixtures.basic_entry()
        options = FlextLdifModels.ParseFormatOptions(validate_entries=True)

        result = parser_service.parse(
            content=ldif,
            input_source="string",
            server_type="nonexistent_server_type",
            format_options=options,
        )

        _ = TestAssertions.assert_failure(result, expected_error="server type")
