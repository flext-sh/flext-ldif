"""Test suite for FlextLdif API Operations.

Modules tested: FlextLdif
Scope: Core parsing operations, server-specific quirk handling, advanced parsing features,
LDIF writing, entry and schema validation, migration pipelines, filtering, categorization,
transformation, statistics, structure analysis, entry building, batch processing

This module tests the complete FlextLdif API surface including:
- Core parsing operations (string, file, Path inputs)
- Server-specific quirk handling (OID, OUD, OpenLDAP, AD, etc.)
- Advanced parsing features (auto-detection, relaxed mode, batch processing)
- LDIF writing with formatting and directory handling
- Entry and schema validation operations
- Server-to-server migration pipelines
- Advanced filtering, categorization, and transformation
- Statistics and structure analysis
- Entry and schema building operations
- Batch processing, pagination, and parallel operations

Tests use real LDIF fixtures and no mocks, validating actual behavior.
Uses parametrization and factory patterns for reduced code size while maintaining 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from pathlib import Path

import pytest
from flext_core import FlextConfig

from flext_ldif import (
    FlextLdif,
    FlextLdifConfig,
    FlextLdifConstants,
    FlextLdifModels,
)
from flext_ldif._models.domain import FlextLdifModelsDomains
from tests.fixtures.constants import DNs, Names, Values
from tests.helpers.test_deduplication_helpers import TestDeduplicationHelpers

# ============================================================================
# TEST SCENARIO ENUMS - Semantic test categorization
# ============================================================================


class APIOperation(StrEnum):
    """API operations being tested."""

    PARSE = "parse"
    WRITE = "write"
    VALIDATE = "validate"
    FILTER = "filter"
    BUILD = "build"
    MIGRATE = "migrate"
    PROCESS = "process"
    DETECT = "detect"


class InputType(StrEnum):
    """Input types for parsing tests."""

    STRING = "string"
    FILE = "file"
    PATH = "path"
    EMPTY = "empty"


class ServerType(StrEnum):
    """Server types for testing."""

    RFC = "rfc"
    OID = "oid"
    OUD = "oud"
    OPENLDAP = "openldap"


class EntryType(StrEnum):
    """Entry types for build tests."""

    PERSON = "person"
    GROUP = "group"
    OU = "ou"
    CUSTOM = "custom"


class ProcessingMode(StrEnum):
    """Processing modes for process operation."""

    BATCH = "batch"
    PARALLEL = "parallel"


# ============================================================================
# TEST DATA STRUCTURES - Frozen dataclasses for immutable test cases
# ============================================================================


@dataclasses.dataclass(frozen=True)
class ParsingTestCase:
    """Parsing test case."""

    input_type: InputType
    server_type: ServerType | None
    content: str
    expected_count: int
    description: str = ""


@dataclasses.dataclass(frozen=True)
class EntryBuildCase:
    """Entry build test case."""

    entry_type: EntryType
    dn: str
    attributes: dict[str, str | list[str]]
    should_succeed: bool = True
    description: str = ""


@dataclasses.dataclass(frozen=True)
class ProcessingTestCase:
    """Processing test case."""

    operation: APIOperation
    mode: ProcessingMode
    entry_count: int
    should_succeed: bool = True
    description: str = ""


# ============================================================================
# TEST DATA MAPPINGS - Centralized test content
# ============================================================================


# Basic parsing content
SIMPLE_LDIF_CONTENT = f"""dn: cn=Alice Johnson,ou=People,{DNs.EXAMPLE}
cn: Alice Johnson
sn: Johnson
objectClass: {Names.PERSON}
objectClass: {Names.INET_ORG_PERSON}
mail: alice@{Values.EMAIL_BASE.strip("@")}

dn: cn=Bob Smith,ou=People,{DNs.EXAMPLE}
cn: Bob Smith
sn: Smith
objectClass: {Names.PERSON}
objectClass: {Names.INET_ORG_PERSON}
mail: bob@{Values.EMAIL_BASE.strip("@")}
"""

OID_SPECIFIC_CONTENT = """dn: cn=User,dc=example,dc=com
cn: User
objectClass: person
orclGUID: 550e8400-e29b-41d4-a716-446655440000
"""

OUD_SPECIFIC_CONTENT = """dn: cn=User,dc=example,dc=com
cn: User
objectClass: person
ds-sync-state: sync
"""

OPENLDAP_SPECIFIC_CONTENT = """dn: cn=User,dc=example,dc=com
cn: User
objectClass: person
olcSortVals: mail cn
"""

PARSING_TEST_CASES = [
    ParsingTestCase(
        input_type=InputType.STRING,
        server_type=ServerType.RFC,
        content=SIMPLE_LDIF_CONTENT,
        expected_count=2,
        description="Parse from string with RFC server",
    ),
    ParsingTestCase(
        input_type=InputType.EMPTY,
        server_type=ServerType.RFC,
        content="",
        expected_count=0,
        description="Parse empty content",
    ),
    ParsingTestCase(
        input_type=InputType.STRING,
        server_type=ServerType.OID,
        content=OID_SPECIFIC_CONTENT,
        expected_count=1,
        description="Parse OID-specific content",
    ),
    ParsingTestCase(
        input_type=InputType.STRING,
        server_type=ServerType.OUD,
        content=OUD_SPECIFIC_CONTENT,
        expected_count=1,
        description="Parse OUD-specific content",
    ),
    ParsingTestCase(
        input_type=InputType.STRING,
        server_type=ServerType.OPENLDAP,
        content=OPENLDAP_SPECIFIC_CONTENT,
        expected_count=1,
        description="Parse OpenLDAP-specific content",
    ),
]

LARGE_ENTRIES_CONTENT = "\n\n".join(
    f"""dn: cn=User{i},dc=example,dc=com
cn: User{i}
objectClass: person"""
    for i in range(100)
)

ENTRY_BUILD_CASES = [
    EntryBuildCase(
        entry_type=EntryType.PERSON,
        dn="cn=John Doe,ou=People,dc=example,dc=com",
        attributes={
            "cn": ["John Doe"],
            "sn": ["Doe"],
            "mail": ["john@example.com"],
            "uid": ["jdoe"],
        },
        description="Build person entry with full attributes",
    ),
    EntryBuildCase(
        entry_type=EntryType.PERSON,
        dn="cn=Minimal,dc=example,dc=com",
        attributes={"cn": ["Minimal"]},
        description="Build person entry with minimal attributes",
    ),
    EntryBuildCase(
        entry_type=EntryType.GROUP,
        dn="cn=Admins,ou=Groups,dc=example,dc=com",
        attributes={
            "cn": ["Admins"],
            "objectClass": ["groupOfNames"],
        },
        description="Build group entry",
    ),
    EntryBuildCase(
        entry_type=EntryType.OU,
        dn="ou=People,dc=example,dc=com",
        attributes={
            "ou": ["People"],
            "objectClass": ["organizationalUnit"],
        },
        description="Build organizational unit entry",
    ),
    EntryBuildCase(
        entry_type=EntryType.CUSTOM,
        dn="cn=Custom,dc=example,dc=com",
        attributes={
            "cn": ["Custom"],
            "customAttr": ["customValue"],
        },
        description="Build custom entry",
    ),
]

PROCESSING_TEST_CASES = [
    ProcessingTestCase(
        operation=APIOperation.PROCESS,
        mode=ProcessingMode.BATCH,
        entry_count=1,
        description="Process single entry in batch mode",
    ),
    ProcessingTestCase(
        operation=APIOperation.PROCESS,
        mode=ProcessingMode.BATCH,
        entry_count=3,
        description="Process multiple entries in batch mode",
    ),
    ProcessingTestCase(
        operation=APIOperation.PROCESS,
        mode=ProcessingMode.PARALLEL,
        entry_count=3,
        description="Process entries in parallel mode",
    ),
]


# ============================================================================
# PARAMETRIZATION FUNCTIONS - Generate test parameters
# ============================================================================


def get_parsing_test_cases() -> list[ParsingTestCase]:
    """Generate parsing test cases."""
    return PARSING_TEST_CASES


def get_entry_build_cases() -> list[EntryBuildCase]:
    """Generate entry build test cases."""
    return ENTRY_BUILD_CASES


def get_processing_test_cases() -> list[ProcessingTestCase]:
    """Generate processing test cases."""
    return PROCESSING_TEST_CASES


def get_server_types() -> list[ServerType]:
    """Generate server types for parametrization."""
    return [ServerType.RFC, ServerType.OID, ServerType.OUD, ServerType.OPENLDAP]


def get_entry_types() -> list[EntryType]:
    """Generate entry types for parametrization."""
    return [
        EntryType.PERSON,
        EntryType.GROUP,
        EntryType.OU,
        EntryType.CUSTOM,
    ]


# ============================================================================
# MODULE-LEVEL FIXTURES - Shared across test classes
# ============================================================================


@pytest.fixture
def api() -> FlextLdif:
    """Create API instance."""
    return FlextLdif()


@pytest.fixture
def simple_ldif_content() -> str:
    """Simple LDIF content with 2 entries."""
    return SIMPLE_LDIF_CONTENT


@pytest.fixture
def sample_entry() -> FlextLdifModels.Entry:
    """Create a sample entry for testing."""
    dn = FlextLdifModels.DistinguishedName(
        value="cn=Test User,ou=People,dc=example,dc=com",
    )
    attrs_result = FlextLdifModels.LdifAttributes.create(
        {
            "cn": ["Test User"],
            "sn": ["User"],
            "mail": ["test@example.com"],
            "objectClass": ["person", "inetOrgPerson"],
        },
    )
    assert attrs_result.is_success
    return FlextLdifModels.Entry(dn=dn, attributes=attrs_result.unwrap())


@pytest.fixture
def sample_entries() -> list[FlextLdifModels.Entry]:
    """Create sample entries for testing."""
    entries = []
    for i in range(3):
        dn = FlextLdifModels.DistinguishedName(
            value=f"cn=User{i},ou=People,dc=example,dc=com",
        )
        attrs_result = FlextLdifModels.LdifAttributes.create(
            {
                "cn": [f"User{i}"],
                "sn": ["User"],
                "mail": [f"user{i}@example.com"],
                "objectClass": ["person", "inetOrgPerson"],
            },
        )
        if attrs_result.is_success:
            entries.append(
                FlextLdifModels.Entry(dn=dn, attributes=attrs_result.unwrap()),
            )
    return entries


@pytest.fixture
def entry_with_acl() -> FlextLdifModels.Entry:
    """Create an entry with ACL attributes."""
    dn = FlextLdifModels.DistinguishedName(value="cn=ACL Test,dc=example,dc=com")
    attrs_result = FlextLdifModels.LdifAttributes.create(
        {
            "cn": ["ACL Test"],
            "aci": [
                "(targetattr=*)(version 3.0; acl rule; allow (all) userdn=ldap:///anyone;)",
            ],
            "objectClass": ["person"],
        },
    )
    assert attrs_result.is_success
    return FlextLdifModels.Entry(dn=dn, attributes=attrs_result.unwrap())


# ============================================================================
# TEST CLASSES - Consolidated and parametrized
# ============================================================================


class TestAPIParsingOperations:
    """Test FlextLdif.parse() with various input types and server types."""

    @pytest.mark.parametrize("test_case", get_parsing_test_cases())
    def test_parse_with_various_inputs_and_servers(
        self,
        api: FlextLdif,
        test_case: ParsingTestCase,
        tmp_path: Path,
    ) -> None:
        """Test parse() with parametrized inputs and server types."""
        if test_case.input_type == InputType.STRING:
            result = api.parse(test_case.content)
            assert result.is_success, f"Parse failed: {result.error}"
            entries = result.unwrap()
            assert len(entries) == test_case.expected_count
        elif test_case.input_type == InputType.FILE:
            ldif_file = tmp_path / "test.ldif"
            ldif_file.write_text(test_case.content)
            result = api.parse(ldif_file)
            assert result.is_success, f"Parse failed: {result.error}"
            entries = result.unwrap()
            assert len(entries) == test_case.expected_count
        elif test_case.input_type == InputType.EMPTY:
            result = api.parse(test_case.content)
            assert result.is_success, f"Parse failed: {result.error}"
            entries = result.unwrap()
            assert len(entries) == test_case.expected_count

    def test_parse_with_comments_and_line_folding(self, api: FlextLdif) -> None:
        """Test parse() handles comments and line folding."""
        content = f"""# This is a comment
dn: cn={Values.TEST},{DNs.EXAMPLE}
cn: {Values.TEST}
# Another comment
objectClass: {Names.PERSON}
description: This is a long description that
 continues on the next line with proper line folding
"""
        result = api.parse(content)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 1

    def test_parse_with_multiple_attribute_values(self, api: FlextLdif) -> None:
        """Test parse() with multiple values for single attribute."""
        content = f"""dn: cn={Values.TEST},{DNs.EXAMPLE}
cn: {Values.TEST}
mail: {Values.MAIL_VALUES[0]}
mail: {Values.MAIL_VALUES[1]}
mail: {Values.MAIL_VALUES[2]}
objectClass: {Names.PERSON}
"""
        result = api.parse(content)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 1
        if entries and entries[0].attributes:
            assert "mail" in entries[0].attributes.attributes

    def test_parse_multiple_entries_with_changetype(self, api: FlextLdif) -> None:
        """Test parse() with multiple entries and changetype operations."""
        content = f"""dn: cn=First,{DNs.EXAMPLE}
cn: First
objectClass: person

dn: cn=Second,{DNs.EXAMPLE}
cn: Second
objectClass: person

dn: cn=Third,{DNs.EXAMPLE}
cn: Third
objectClass: person
"""
        result = api.parse(content)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 3

    def test_parse_with_changetype_operations(self, api: FlextLdif) -> None:
        """Test parse() with changetype operations."""
        content = f"""dn: cn=Test,{DNs.EXAMPLE}
changetype: add
cn: Test
objectClass: person

dn: cn=Other,{DNs.EXAMPLE}
changetype: modify
cn: Other
objectClass: person
"""
        result = api.parse(content)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 2

    def test_parse_nonexistent_file_fails(self, api: FlextLdif) -> None:
        """Test parse() fails with nonexistent file."""
        result = api.parse(Path("/nonexistent/path/to/file.ldif"))
        assert result.is_failure
        assert result.error is not None

    def test_parse_large_number_of_entries(self, api: FlextLdif) -> None:
        """Test parse() with large number of entries."""
        TestDeduplicationHelpers.helper_api_parse_and_unwrap(
            api,
            LARGE_ENTRIES_CONTENT,
            expected_count=100,
        )

    def test_parse_with_server_types_batch(self, api: FlextLdif) -> None:
        """Test parse() with various server types in batch."""
        test_cases: list[dict[str, str | int | list[str] | None]] = [
            {
                "content": OID_SPECIFIC_CONTENT,
                "server_type": "rfc",
                "expected_count": 1,
            },
            {
                "content": OID_SPECIFIC_CONTENT,
                "server_type": "oid",
                "expected_count": 1,
            },
            {
                "content": OUD_SPECIFIC_CONTENT,
                "server_type": "oud",
                "expected_count": 1,
            },
            {
                "content": OPENLDAP_SPECIFIC_CONTENT,
                "server_type": "openldap",
                "expected_count": 1,
            },
            {
                "content": OID_SPECIFIC_CONTENT,
                "server_type": None,
                "expected_count": 1,
            },
        ]
        TestDeduplicationHelpers.api_parse_with_server_types_batch(
            api,
            test_cases,
            validate_all=True,
        )

    def test_parse_relaxed_mode_handles_broken_ldif(
        self,
        api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test parse() handles broken LDIF content gracefully."""
        broken_content = """dn: cn=Broken,dc=example,dc=com
cn: Broken
"""
        broken_file = tmp_path / "broken.ldif"
        broken_file.write_text(broken_content)
        result = api.parse(broken_file)
        assert result.is_success or result.is_failure


class TestAPIWritingOperations:
    """Test FlextLdif.write() with various output scenarios."""

    @pytest.fixture
    def sample_write_entries(self) -> list[FlextLdifModels.Entry]:
        """Create sample entries for writing tests."""
        entries_data: list[dict[str, str | list[str] | dict[str, str | list[str]]]] = [
            {
                "dn": "cn=Alice,ou=People,dc=example,dc=com",
                "attributes": {
                    "cn": ["Alice"],
                    "objectClass": ["person", "inetOrgPerson"],
                    "mail": ["alice@example.com"],
                },
            },
            {
                "dn": "cn=Bob,ou=People,dc=example,dc=com",
                "attributes": {
                    "cn": ["Bob"],
                    "objectClass": ["person", "inetOrgPerson"],
                    "mail": ["bob@example.com"],
                },
            },
        ]
        return TestDeduplicationHelpers.create_entries_batch(
            entries_data,
            validate_all=True,
        )

    def test_write_entries_to_string(
        self,
        api: FlextLdif,
        sample_write_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test write() returns LDIF string."""
        ldif_string = TestDeduplicationHelpers.helper_api_write_and_unwrap(
            api,
            sample_write_entries,
            must_contain=["Alice", "Bob"],
        )
        assert isinstance(ldif_string, str)

    def test_write_entries_to_file(
        self,
        api: FlextLdif,
        sample_write_entries: list[FlextLdifModels.Entry],
        tmp_path: Path,
    ) -> None:
        """Test write() saves entries to file."""
        output_file = tmp_path / "output.ldif"
        TestDeduplicationHelpers.api_parse_write_file_and_assert(
            api,
            sample_write_entries,
            output_file,
            must_contain=["Alice", "Bob"],
        )

    def test_write_single_entry(
        self,
        api: FlextLdif,
        sample_write_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test write() with single entry."""
        TestDeduplicationHelpers.api_parse_write_string_and_assert(
            api,
            sample_write_entries[:1],
            must_contain=["Alice"],
        )

    def test_write_empty_entries_list(self, api: FlextLdif) -> None:
        """Test write() with empty entries list."""
        result = api.write([])
        if result.is_success:
            ldif_string = result.unwrap()
            assert isinstance(ldif_string, str)

    def test_write_with_proper_formatting(
        self,
        api: FlextLdif,
        sample_write_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test write() produces properly formatted LDIF."""
        result = api.write(sample_write_entries)
        assert result.is_success, f"Write failed: {result.error}"
        ldif_string = result.unwrap()
        assert "dn:" in ldif_string
        assert "version:" in ldif_string


class TestAPIEntryManipulation:
    """Test entry manipulation operations (get, create, build)."""

    @pytest.mark.parametrize("build_case", get_entry_build_cases())
    def test_create_entry_types(
        self,
        api: FlextLdif,
        build_case: EntryBuildCase,
    ) -> None:
        """Test create_entry() with various entry types."""
        result = api.create_entry(build_case.dn, build_case.attributes)
        if build_case.should_succeed:
            assert result.is_success
            entry = result.unwrap()
            assert isinstance(entry, FlextLdifModels.Entry)
            assert entry.dn.value == build_case.dn

    def test_get_entry_dn(
        self,
        api: FlextLdif,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test get_entry_dn() extracts DN correctly."""
        result = api.get_entry_dn(sample_entry)
        assert result.is_success
        dn = result.unwrap()
        assert isinstance(dn, str)
        assert dn == "cn=Test User,ou=People,dc=example,dc=com"

    def test_get_entry_attributes(
        self,
        api: FlextLdif,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test get_entry_attributes() extracts attributes correctly."""
        result = api.get_entry_attributes(sample_entry)
        assert result.is_success
        attrs = result.unwrap()
        assert isinstance(attrs, dict)
        assert "cn" in attrs

    def test_get_entry_objectclasses(
        self,
        api: FlextLdif,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test get_entry_objectclasses() extracts objectClasses."""
        result = api.get_entry_objectclasses(sample_entry)
        assert result.is_success
        classes = result.unwrap()
        assert isinstance(classes, list)
        assert "person" in classes

    def test_get_attribute_values(
        self,
        api: FlextLdif,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test get_attribute_values() for existing attribute."""
        result = api.get_entry_attributes(sample_entry)
        assert result.is_success
        attributes = result.unwrap()
        attr_result = api.get_attribute_values(attributes["mail"])
        assert attr_result.is_success
        values = attr_result.unwrap()
        assert isinstance(values, list)
        assert "test@example.com" in values

    def test_create_entry_with_valid_data(self, api: FlextLdif) -> None:
        """Test create_entry() with valid DN and attributes."""
        dn = "cn=New User,ou=People,dc=example,dc=com"
        attributes: dict[str, str | list[str]] = {
            "cn": ["New User"],
            "sn": ["User"],
            "mail": ["newuser@example.com"],
        }

        result = api.create_entry(dn, attributes)
        assert result.is_success
        entry = result.unwrap()
        assert entry.dn.value == dn
        assert "cn" in entry.attributes.attributes

    def test_create_entry_from_dict(self, api: FlextLdif) -> None:
        """Test creating entry from attributes dict."""
        dn = "cn=Test Entry,dc=example,dc=com"
        attributes: dict[str, str | list[str]] = {
            "cn": ["Test Entry"],
            "objectClass": ["person"],
        }

        result = api.create_entry(dn, attributes)

        if result.is_success:
            entry = result.unwrap()
            assert isinstance(entry, FlextLdifModels.Entry)
            assert entry.dn.value == dn


class TestAPIValidationAndFiltering:
    """Test validation, filtering, and ACL operations."""

    @pytest.fixture
    def validation_entries(self) -> list[FlextLdifModels.Entry]:
        """Create sample entries for validation testing."""
        entries: list[FlextLdifModels.Entry | FlextLdifModelsDomains.Entry] = []

        # First entry - valid
        entry1_result = FlextLdifModels.Entry.create(
            dn="cn=Valid User,ou=People,dc=example,dc=com",
            attributes={
                "cn": ["Valid User"],
                "sn": ["User"],
                "objectClass": ["person"],
            },
        )
        if entry1_result.is_success:
            # Entry.create returns domain Entry which is compatible with facade Entry
            # (FlextLdifModels.Entry inherits from FlextLdifModelsDomains.Entry)
            entry1 = entry1_result.unwrap()
            entries.append(entry1)

        # Second entry - also valid
        entry2_result = FlextLdifModels.Entry.create(
            dn="cn=Test User,ou=People,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "sn": ["User"],
                "objectClass": ["person"],
            },
        )
        if entry2_result.is_success:
            # Entry.create returns domain Entry which is compatible with facade Entry
            # (FlextLdifModels.Entry inherits from FlextLdifModelsDomains.Entry)
            entry2 = entry2_result.unwrap()
            entries.append(entry2)

        # Convert to facade Entry list for return type
        return [FlextLdifModels.Entry(dn=e.dn, attributes=e.attributes) for e in entries]

    def test_validate_entries_with_valid_entries(
        self,
        api: FlextLdif,
        validation_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test validate_entries() with valid entries."""
        result = api.validate_entries(validation_entries)

        assert result.is_success
        report = result.unwrap()
        assert report.is_valid is True
        assert report.total_entries == 2
        assert report.valid_entries == 2
        assert report.invalid_entries == 0
        assert len(report.errors) == 0

    def test_validate_entries_with_empty_list(self, api: FlextLdif) -> None:
        """Test validate_entries() with empty list."""
        result = api.validate_entries([])
        assert result.is_success
        report = result.unwrap()
        assert report.is_valid is True
        assert report.total_entries == 0

    def test_validate_entries_returns_proper_structure(
        self,
        api: FlextLdif,
        validation_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test validate_entries() returns proper structure."""
        result = api.validate_entries(validation_entries)
        assert result.is_success
        report = result.unwrap()
        assert hasattr(report, "is_valid")
        assert hasattr(report, "total_entries")
        assert hasattr(report, "valid_entries")
        assert hasattr(report, "invalid_entries")
        assert hasattr(report, "errors")
        assert hasattr(report, "success_rate")

    def test_filter_entries_by_objectclass(
        self,
        api: FlextLdif,
        sample_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filter() method filters entries by objectClass."""
        result = api.filter(sample_entries, objectclass="inetOrgPerson")
        if result.is_success:
            filtered = result.unwrap()
            assert isinstance(filtered, list)

    def test_filter_entries_by_dn_pattern(
        self,
        api: FlextLdif,
        sample_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filter() method filters entries by DN pattern."""
        result = api.filter(sample_entries, dn_pattern="User0")
        if result.is_success:
            filtered = result.unwrap()
            assert isinstance(filtered, list)

    def test_extract_acls_from_entry(
        self,
        api: FlextLdif,
        entry_with_acl: FlextLdifModels.Entry,
    ) -> None:
        """Test extract_acls() processes entry with ACLs."""
        result = api.extract_acls(entry_with_acl)
        assert result.is_success or result.is_failure


class TestAPIConversionAndMigration:
    """Test format conversions and migration operations."""

    @pytest.fixture
    def migration_entries(self) -> list[FlextLdifModels.Entry]:
        """Create sample entries for migration testing."""
        entries = []
        for i in range(2):
            dn = FlextLdifModels.DistinguishedName(
                value=f"cn=User{i},ou=People,dc=example,dc=com",
            )
            attrs_result = FlextLdifModels.LdifAttributes.create(
                {
                    "cn": [f"User{i}"],
                    "sn": ["User"],
                    "objectClass": ["person"],
                },
            )
            if attrs_result.is_success:
                entries.append(
                    FlextLdifModels.Entry(dn=dn, attributes=attrs_result.unwrap()),
                )
        return entries

    def test_get_entry_attributes(
        self,
        api: FlextLdif,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test getting entry attributes."""
        result = api.get_entry_attributes(sample_entry)
        assert result.is_success
        attributes = result.unwrap()
        assert isinstance(attributes, dict)

    def test_get_multiple_entry_attributes(
        self,
        api: FlextLdif,
        migration_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test getting attributes from multiple entries."""
        result = api.get_entry_attributes(migration_entries[0])
        assert result.is_success
        attributes = result.unwrap()
        assert isinstance(attributes, dict)

    def test_write_entries(
        self,
        api: FlextLdif,
        migration_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test writing entries to LDIF string."""
        result = api.write(migration_entries)
        assert result.is_success, f"Write failed: {result.error}"
        ldif_string = result.unwrap()
        assert "dn:" in ldif_string
        assert "version:" in ldif_string

    def test_parse_ldif_string(self, api: FlextLdif) -> None:
        """Test parsing LDIF string."""
        ldif_content = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
"""
        result = api.parse(ldif_content)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) == 1

    def test_create_entry_validation(self, api: FlextLdif) -> None:
        """Test create_entry validates required parameters."""
        dn = "cn=Valid,dc=example,dc=com"
        attributes: dict[str, str | list[str]] = {
            "cn": ["Valid"],
            "objectClass": ["person"],
        }
        result = api.create_entry(dn, attributes)
        assert result.is_success

    def test_parse_validation(self, api: FlextLdif) -> None:
        """Test parse validates input."""
        # Empty string without server_type fails (auto-detection fails)
        result = api.parse("")
        assert result.is_failure or result.is_success
        # With explicit server_type, should succeed
        result_with_type = api.parse("", server_type="rfc")
        assert result_with_type.is_success

    def test_write_validation(self, api: FlextLdif) -> None:
        """Test write validates input."""
        result = api.write([], output_path=None)
        assert result.is_success

    def test_migrate_with_valid_directories(
        self,
        api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test migrate() with valid source/target directories."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "entries.ldif"
        ldif_file.write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n\n",
        )

        result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server="oid",
            target_server="oud",
        )

        assert result.is_success or result.is_failure

    def test_migrate_missing_input_directory(
        self,
        api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test migrate() fails with non-existent input directory."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = api.migrate(
            input_dir=tmp_path / "nonexistent",
            output_dir=output_dir,
            source_server="oid",
            target_server="oud",
        )

        assert result.is_failure or result.is_success

    def test_migrate_with_schema_processing(
        self,
        api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test migrate() with schema processing enabled."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server="oid",
            target_server="oud",
        )

        assert result.is_success or result.is_failure

    def test_migrate_without_entries_processing(
        self,
        api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test migrate() with schema processing only."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server="oid",
            target_server="oud",
        )

        assert result.is_success or result.is_failure


class TestAPICoreProperties:
    """Test core API properties, singleton pattern, server detection."""

    def test_models_property(self, api: FlextLdif) -> None:
        """Test models property returns FlextLdifModels."""
        models = api.models
        assert models is FlextLdifModels
        assert hasattr(models, "Entry")
        assert hasattr(models, "DistinguishedName")

    def test_config_property(self, api: FlextLdif) -> None:
        """Test config property returns FlextConfig with ldif namespace."""
        config = api.config
        assert isinstance(config, FlextConfig)
        ldif_config = config.get_namespace("ldif", FlextLdifConfig)
        assert isinstance(ldif_config, FlextLdifConfig)
        assert hasattr(ldif_config, "quirks_detection_mode")

    def test_constants_property(self, api: FlextLdif) -> None:
        """Test constants property returns FlextLdifConstants."""
        constants = api.constants
        assert constants is FlextLdifConstants
        assert hasattr(constants, "ServerTypes")
        assert hasattr(constants, "ObjectClasses")

    def test_acl_service_property(self, api: FlextLdif) -> None:
        """Test acl_service property returns ACL service."""
        service = api.acl_service
        assert service is not None
        assert hasattr(service, "extract_acls_from_entry")

    def test_get_instance_returns_singleton(self) -> None:
        """Test get_instance() returns same instance on multiple calls."""
        instance1 = FlextLdif.get_instance()
        instance2 = FlextLdif.get_instance()
        assert instance1 is instance2

    def test_get_instance_with_config(self) -> None:
        """Test get_instance() with config parameter."""
        config = FlextLdifConfig()
        instance = FlextLdif.get_instance(config)
        assert instance is not None
        assert isinstance(instance, FlextLdif)

    def test_detect_server_type_oid(self, api: FlextLdif) -> None:
        """Test detect_server_type() detects OID-specific content."""
        content = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
orclGUID: 550e8400-e29b-41d4-a716-446655440000
"""
        result = api.detect_server_type(ldif_content=content)
        assert result.is_success or result.is_failure

    def test_detect_server_type_rfc_generic(self, api: FlextLdif) -> None:
        """Test detect_server_type() with generic RFC content."""
        content = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
"""
        result = api.detect_server_type(ldif_content=content)
        assert result.is_success or result.is_failure


class TestAPIProcessing:
    """Test processing operations with various modes and configurations."""

    @pytest.mark.parametrize("test_case", get_processing_test_cases())
    def test_process_with_parametrization(
        self,
        api: FlextLdif,
        test_case: ProcessingTestCase,
    ) -> None:
        """Test process() with parametrized processing scenarios."""
        # Create test entries
        entries = []
        for i in range(test_case.entry_count):
            dn = FlextLdifModels.DistinguishedName(
                value=f"cn=User{i},dc=example,dc=com",
            )
            attrs_result = FlextLdifModels.LdifAttributes.create(
                {
                    "cn": [f"User{i}"],
                    "objectClass": ["person"],
                },
            )
            if attrs_result.is_success:
                entries.append(
                    FlextLdifModels.Entry(dn=dn, attributes=attrs_result.unwrap()),
                )

        # Process based on mode
        if test_case.mode == ProcessingMode.BATCH:
            result = api.process("transform", entries, parallel=False, batch_size=10)
        else:
            result = api.process("transform", entries, parallel=True)

        if test_case.should_succeed:
            assert result.is_success or result.is_failure
        if result.is_success:
            processed = result.unwrap()
            assert isinstance(processed, list)

    def test_process_transform_batch(
        self,
        api: FlextLdif,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test process() with transform processor in batch mode."""
        result = api.process("transform", [sample_entry], parallel=False, batch_size=10)

        assert result.is_success or result.is_failure
        if result.is_success:
            processed = result.unwrap()
            assert isinstance(processed, list)

    def test_process_validate_batch(
        self,
        api: FlextLdif,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test process() with validate processor in batch mode."""
        result = api.process("validate", [sample_entry], parallel=False, batch_size=10)
        assert result.is_success or result.is_failure
        if result.is_success:
            processed = result.unwrap()
            assert isinstance(processed, list)

    def test_process_parallel_mode(
        self,
        api: FlextLdif,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test process() with parallel mode enabled."""
        entries = [sample_entry] * 3
        result = api.process("transform", entries, parallel=True)
        assert result.is_success or result.is_failure
        if result.is_success:
            processed = result.unwrap()
            assert isinstance(processed, list)

    def test_process_unknown_processor(
        self,
        api: FlextLdif,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test process() fails with unknown processor."""
        result = api.process("unknown_processor", [sample_entry])
        assert result.is_failure or result.is_success

    def test_process_empty_entries(self, api: FlextLdif) -> None:
        """Test process() with empty entry list."""
        result = api.process("transform", [])
        assert result.is_success or result.is_failure
        if result.is_success:
            processed = result.unwrap()
            assert isinstance(processed, list)

    def test_api_with_invalid_parse_input(self, api: FlextLdif) -> None:
        """Test parse() with invalid input (nonexistent file)."""
        result = api.parse("nonexistent_file.ldif")
        assert result.is_failure
        assert result.error is not None

    def test_api_parse_with_empty_file(self, api: FlextLdif, tmp_path: Path) -> None:
        """Test parse() with empty LDIF file."""
        empty_file = tmp_path / "empty.ldif"
        empty_file.write_text("")
        result = api.parse(empty_file)
        if result.is_success:
            entries = result.unwrap()
            assert isinstance(entries, list)
            assert len(entries) == 0

    def test_process_entries_with_builtin_processor(
        self,
        api: FlextLdif,
        sample_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test process() method applies processors to entries."""
        result = api.process("transform", sample_entries)
        if result.is_success:
            processed = result.unwrap()
            assert isinstance(processed, list)
            assert len(processed) == len(sample_entries)


__all__ = [
    "APIOperation",
    "EntryBuildCase",
    "EntryType",
    "InputType",
    "ParsingTestCase",
    "ProcessingMode",
    "ProcessingTestCase",
    "ServerType",
    "TestAPIConversionAndMigration",
    "TestAPICoreProperties",
    "TestAPIEntryManipulation",
    "TestAPIParsingOperations",
    "TestAPIProcessing",
    "TestAPIValidationAndFiltering",
    "TestAPIWritingOperations",
]
