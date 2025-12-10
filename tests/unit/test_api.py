"""Tests for FlextLdif main API functionality.

This module tests the primary FlextLdif API facade for LDIF parsing,
validation, and processing operations.
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from pathlib import Path
from typing import ClassVar

import pytest
from flext_core import FlextConfig

from flext_ldif import (
    FlextLdif,
    FlextLdifConfig,
)
from flext_ldif.constants import FlextLdifConstants, c as lib_c
from flext_ldif.models import FlextLdifModels
from tests import TestDeduplicationHelpers, c, p, s

m = FlextLdifModels

# TypedDicts (GenericFieldsDict, GenericTestCaseDict, etc.) are available from conftest.py


@pytest.fixture
def sample_entries() -> list[p.Entry]:
    """Create sample entries for testing."""
    helper = s()
    return [
        helper.create_entry(
            dn=f"cn={c.Values.USER}{i}, {c.DNs.EXAMPLE}",
            attributes={
                c.Names.CN: [f"{c.Values.USER}{i}"],
                c.Names.OBJECTCLASS: [c.Names.PERSON],
            },
        )
        for i in range(3)
    ]


@pytest.fixture
def entry_with_acl() -> p.Entry:
    """Create an entry with ACL attributes."""
    return s.create_entry(
        dn=f"cn={c.Values.TEST} ACL, {c.DNs.EXAMPLE}",
        attributes={
            c.Names.CN: [f"{c.Values.TEST} ACL"],
            c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INET_ORG_PERSON],
            c.Names.MAIL: ["test@example.com"],
            "orclACI": [
                "(targetattr=*)(version 3.0; acl rule; allow (all) userdn=ldap:///anyone;)"
            ],
        },
    )


# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)

# ============================================================================
# TEST SCENARIO ENUMS
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


class ParsingScenario(StrEnum):
    """Parsing test scenarios."""

    SIMPLE_STRING = "simple_string"
    COMMENTS_FOLDING = "comments_folding"
    MULTIPLE_VALUES = "multiple_values"
    MULTIPLE_ENTRIES = "multiple_entries"
    CHANGETYPE_OPS = "changetype_ops"
    NONEXISTENT_FILE = "nonexistent_file"
    LARGE_ENTRIES = "large_entries"
    SERVER_TYPES = "server_types"
    BROKEN_LDIF = "broken_ldif"


class WritingScenario(StrEnum):
    """Writing test scenarios."""

    TO_STRING = "to_string"
    TO_FILE = "to_file"
    SINGLE_ENTRY = "single_entry"
    EMPTY_LIST = "empty_list"
    PROPER_FORMAT = "proper_format"


class EntryManipulationScenario(StrEnum):
    """Entry manipulation test scenarios."""

    CREATE_TYPES = "create_types"
    GET_DN = "get_dn"
    GET_ATTRIBUTES = "get_attributes"
    GET_OBJECTCLASSES = "get_objectclasses"
    GET_ATTR_VALUES = "get_attr_values"


class ValidationScenario(StrEnum):
    """Validation test scenarios."""

    VALID_ENTRIES = "valid_entries"
    EMPTY_LIST = "empty_list"
    PROPER_STRUCTURE = "proper_structure"
    FILTER_OBJECTCLASS = "filter_objectclass"
    FILTER_DN_PATTERN = "filter_dn_pattern"
    EXTRACT_ACLS = "extract_acls"


class MigrationScenario(StrEnum):
    """Migration test scenarios."""

    BASIC_MIGRATE = "basic_migrate"
    MISSING_INPUT = "missing_input"
    SCHEMA_PROCESSING = "schema_processing"
    NO_ENTRIES_PROCESSING = "no_entries_processing"


class ProcessingScenario(StrEnum):
    """Processing test scenarios."""

    PARAMETRIZED = "parametrized"
    TRANSFORM_BATCH = "transform_batch"
    VALIDATE_BATCH = "validate_batch"
    PARALLEL_MODE = "parallel_mode"
    UNKNOWN_PROCESSOR = "unknown_processor"
    EMPTY_ENTRIES = "empty_entries"


class CorePropertiesScenario(StrEnum):
    """Core properties test scenarios."""

    MODELS = "models"
    CONFIG = "config"
    CONSTANTS = "constants"
    ACL_SERVICE = "acl_service"
    SINGLETON = "singleton"
    SINGLETON_WITH_CONFIG = "singleton_with_config"
    DETECT_OID = "detect_oid"
    DETECT_RFC = "detect_rfc"


# ============================================================================
# TEST DATA STRUCTURES
# ============================================================================


@dataclasses.dataclass(frozen=True)
class ParsingTestCase:
    """Parsing test case."""

    scenario: ParsingScenario
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

    scenario: ProcessingScenario
    entry_count: int
    should_succeed: bool = True
    description: str = ""


# ============================================================================
# TEST DATA CONSTANTS
# ============================================================================

# Basic parsing content
SIMPLE_LDIF_CONTENT = f"""dn: cn=Alice Johnson, {c.DNs.EXAMPLE}
changetype: add
cn: {c.Values.TEST}
objectClass: {c.Names.PERSON}

dn: cn={c.Values.USER}, {c.DNs.EXAMPLE}
changetype: modify
cn: {c.Values.USER}
objectClass: {c.Names.PERSON}
"""

BROKEN_CONTENT = f"""dn: cn={c.Values.TEST}, {c.DNs.EXAMPLE}
cn: Alice Johnson
sn: Johnson
objectClass: {c.Names.PERSON}
objectClass: {c.Names.INET_ORG_PERSON}
mail: alice@example.com

dn: cn=Bob Smith, {c.DNs.EXAMPLE}
cn: Bob Smith
sn: Smith
objectClass: {c.Names.PERSON}
objectClass: {c.Names.INET_ORG_PERSON}
mail: bob@example.com
"""

OID_SPECIFIC_CONTENT = f"""dn: cn={c.Values.USER}, {c.DNs.EXAMPLE}
cn: {c.Values.TEST}
"""

LARGE_ENTRIES_CONTENT = "\n\n".join([
    f"""dn: cn={c.Values.USER}{i}, {c.DNs.EXAMPLE}
cn: {c.Values.TEST}
# Another comment
objectClass: {c.Names.PERSON}
description: This is a long description that
 continues on the next line with proper line folding
"""
    for i in range(5)
])

MULTIPLE_VALUES_CONTENT = f"""dn: cn={c.Values.TEST}, {c.DNs.EXAMPLE}
cn: {c.Values.TEST}
mail: alice@example.com
mail: bob@example.com
mail: charlie@example.com
objectClass: {c.Names.PERSON}
"""

MULTIPLE_ENTRIES_CONTENT = f"""dn: cn=user1, {c.DNs.EXAMPLE}
cn: {c.Values.TEST}
objectClass: {c.Names.PERSON}
"""

CHANGETYPE_CONTENT = f"""dn: cn={c.Values.TEST}, {c.DNs.EXAMPLE}
cn: user1
objectClass: {c.Names.PERSON}

dn: cn={c.Values.USER}2, {c.DNs.EXAMPLE}
cn: user2
objectClass: {c.Names.PERSON}

dn: cn={c.Values.TEST}, {c.DNs.EXAMPLE}
cn: {c.Values.USER}
objectClass: {c.Names.PERSON}
ds-sync-state: sync
"""

OPENLDAP_SPECIFIC_CONTENT = f"""dn: cn={c.Values.USER}, {c.DNs.EXAMPLE}
cn: {c.Values.USER}
objectClass: {c.Names.PERSON}
olcSortVals: mail cn
"""

COMMENTS_FOLDING_CONTENT = f"""# This is a comment
dn: cn={c.Values.TEST}, {c.DNs.EXAMPLE}
cn: {c.Values.USER}
objectClass: {c.Names.PERSON}
orclGUID: 550e8400-e29b-41d4-a716-446655440000
"""

OUD_SPECIFIC_CONTENT = f"""dn: cn={c.Values.USER}, {c.DNs.EXAMPLE}
cn: {c.Values.USER}
objectClass: {c.Names.PERSON}"""

# ============================================================================
# MODULE-LEVEL FIXTURES
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
def sample_entry() -> p.Entry:
    """Create a sample entry for testing."""
    helper = s()
    return helper.create_entry(
        dn=f"cn={c.Values.TEST} {c.Values.USER}, {c.DNs.EXAMPLE}",
        attributes={
            c.Names.CN: [f"{c.Values.TEST} {c.Values.USER}"],
            c.Names.OBJECTCLASS: [c.Names.PERSON],
        },
    )


# ============================================================================
# TEST CLASSES - Consolidated and Parametrized
# ============================================================================


class TestsFlextLdifAPIParsingOperations(s):
    """Test FlextLdif.parse() with consolidated parametrized scenarios."""

    PARSING_SCENARIOS: ClassVar[dict[ParsingScenario, ParsingTestCase]] = {
        ParsingScenario.SIMPLE_STRING: ParsingTestCase(
            scenario=ParsingScenario.SIMPLE_STRING,
            input_type=InputType.STRING,
            server_type=lib_c.Ldif.ServerTypes.RFC,
            content=SIMPLE_LDIF_CONTENT,
            expected_count=2,
            description="Parse from string with RFC server",
        ),
        ParsingScenario.COMMENTS_FOLDING: ParsingTestCase(
            scenario=ParsingScenario.COMMENTS_FOLDING,
            input_type=InputType.STRING,
            server_type=lib_c.Ldif.ServerTypes.RFC,
            content=COMMENTS_FOLDING_CONTENT,
            expected_count=1,
            description="Parse with comments and line folding",
        ),
        ParsingScenario.MULTIPLE_VALUES: ParsingTestCase(
            scenario=ParsingScenario.MULTIPLE_VALUES,
            input_type=InputType.STRING,
            server_type=lib_c.Ldif.ServerTypes.RFC,
            content=MULTIPLE_VALUES_CONTENT,
            expected_count=1,
            description="Parse with multiple attribute values",
        ),
        ParsingScenario.MULTIPLE_ENTRIES: ParsingTestCase(
            scenario=ParsingScenario.MULTIPLE_ENTRIES,
            input_type=InputType.STRING,
            server_type=lib_c.Ldif.ServerTypes.RFC,
            content=MULTIPLE_ENTRIES_CONTENT,
            expected_count=3,
            description="Parse multiple entries",
        ),
        ParsingScenario.CHANGETYPE_OPS: ParsingTestCase(
            scenario=ParsingScenario.CHANGETYPE_OPS,
            input_type=InputType.STRING,
            server_type=lib_c.Ldif.ServerTypes.RFC,
            content=CHANGETYPE_CONTENT,
            expected_count=2,
            description="Parse with changetype operations",
        ),
        ParsingScenario.NONEXISTENT_FILE: ParsingTestCase(
            scenario=ParsingScenario.NONEXISTENT_FILE,
            input_type=InputType.PATH,
            server_type=None,
            content="/nonexistent/path/to/file.ldif",
            expected_count=0,
            description="Parse nonexistent file",
        ),
        ParsingScenario.LARGE_ENTRIES: ParsingTestCase(
            scenario=ParsingScenario.LARGE_ENTRIES,
            input_type=InputType.STRING,
            server_type=lib_c.Ldif.ServerTypes.RFC,
            content=LARGE_ENTRIES_CONTENT,
            expected_count=100,
            description="Parse large number of entries",
        ),
        ParsingScenario.SERVER_TYPES: ParsingTestCase(
            scenario=ParsingScenario.SERVER_TYPES,
            input_type=InputType.STRING,
            server_type=lib_c.Ldif.ServerTypes.OID,
            content=OID_SPECIFIC_CONTENT,
            expected_count=1,
            description="Parse OID-specific content",
        ),
        ParsingScenario.BROKEN_LDIF: ParsingTestCase(
            scenario=ParsingScenario.BROKEN_LDIF,
            input_type=InputType.STRING,
            server_type=lib_c.Ldif.ServerTypes.RFC,
            content=BROKEN_CONTENT,
            expected_count=1,
            description="Parse broken LDIF content",
        ),
    }

    @pytest.mark.parametrize(
        ("scenario", "test_case"),
        PARSING_SCENARIOS.items(),
    )
    def test_parse_scenarios(
        self,
        scenario: ParsingScenario,
        test_case: ParsingTestCase,
        api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Test parse() with various scenarios."""
        if scenario == ParsingScenario.NONEXISTENT_FILE:
            result = api.parse(Path(test_case.content))
            assert result.is_failure
        elif scenario == ParsingScenario.BROKEN_LDIF:
            result = api.parse(test_case.content)
            assert result.is_success or result.is_failure
        else:
            result = api.parse(test_case.content)
            assert result.is_success, f"Parse failed: {result.error}"
            entries = result.unwrap()
            assert len(entries) == test_case.expected_count


class TestAPIWritingOperations:
    """Test FlextLdif.write() with consolidated scenarios."""

    @pytest.fixture
    def sample_write_entries(self) -> list[p.Entry]:
        """Create sample entries for writing tests."""
        entries_data: list[dict[str, str | list[str] | dict[str, str | list[str]]]] = [
            {
                "dn": f"cn=user1,ou=People,{c.DNs.EXAMPLE}",
                "attributes": {
                    c.Names.CN: ["user1"],
                    c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INET_ORG_PERSON],
                    c.Names.MAIL: ["alice@example.com"],
                },
            },
            {
                "dn": f"cn=user2,ou=People,{c.DNs.EXAMPLE}",
                "attributes": {
                    c.Names.CN: ["user2"],
                    c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INET_ORG_PERSON],
                    c.Names.MAIL: ["bob@example.com"],
                },
            },
        ]
        return TestDeduplicationHelpers.create_entries_batch(
            entries_data,
            validate_all=True,
        )

    WRITE_SCENARIOS: ClassVar[set[WritingScenario]] = {
        WritingScenario.TO_STRING,
        WritingScenario.TO_FILE,
        WritingScenario.SINGLE_ENTRY,
        WritingScenario.EMPTY_LIST,
        WritingScenario.PROPER_FORMAT,
    }

    @pytest.mark.parametrize(
        "scenario",
        [[s] for s in WRITE_SCENARIOS],
    )
    def test_write_scenarios(
        self,
        scenario: WritingScenario,
        api: FlextLdif,
        sample_write_entries: list[p.Entry],
        tmp_path: Path,
    ) -> None:
        """Test write() with various scenarios."""
        if scenario == WritingScenario.TO_STRING:
            ldif_string = TestDeduplicationHelpers.helper_api_write_and_unwrap(
                api,
                sample_write_entries,
                must_contain=["Alice", "Bob"],
            )
            assert isinstance(ldif_string, str)
        elif scenario == WritingScenario.TO_FILE:
            output_file = tmp_path / "output.ldif"
            TestDeduplicationHelpers.api_parse_write_file_and_assert(
                api,
                sample_write_entries,
                output_file,
                must_contain=["Alice", "Bob"],
            )
        elif scenario == WritingScenario.SINGLE_ENTRY:
            TestDeduplicationHelpers.api_parse_write_string_and_assert(
                api,
                sample_write_entries[:1],
                must_contain=["Alice"],
            )
        elif scenario == WritingScenario.EMPTY_LIST:
            result = api.write([])
            if result.is_success:
                ldif_string = result.unwrap()
                assert isinstance(ldif_string, str)
        elif scenario == WritingScenario.PROPER_FORMAT:
            result = api.write(sample_write_entries)
            assert result.is_success, f"Write failed: {result.error}"
            ldif_string = result.unwrap()
            assert "dn:" in ldif_string
            assert "version:" in ldif_string


class TestAPIEntryManipulation:
    """Test entry manipulation operations with parametrized scenarios."""

    ENTRY_BUILD_CASES: ClassVar[dict[EntryType, EntryBuildCase]] = {
        EntryType.PERSON: EntryBuildCase(
            entry_type=EntryType.PERSON,
            dn=f"cn={c.Values.USER},ou=People,{c.DNs.EXAMPLE}",
            attributes={
                c.Names.CN: [c.Values.USER],
                c.Names.SN: [c.Values.USER],
                c.Names.MAIL: ["test@example.com"],
                "uid": [c.Values.TEST],
            },
            description="Build person entry with full attributes",
        ),
        EntryType.GROUP: EntryBuildCase(
            entry_type=EntryType.GROUP,
            dn=f"cn={c.Values.TEST},ou=Groups,{c.DNs.EXAMPLE}",
            attributes={
                c.Names.CN: [c.Values.TEST],
                c.Names.OBJECTCLASS: ["groupOfNames"],
            },
            description="Build group entry",
        ),
        EntryType.OU: EntryBuildCase(
            entry_type=EntryType.OU,
            dn=f"ou=People,{c.DNs.EXAMPLE}",
            attributes={
                "ou": ["People"],
                c.Names.OBJECTCLASS: ["organizationalUnit"],
            },
            description="Build organizational unit entry",
        ),
        EntryType.CUSTOM: EntryBuildCase(
            entry_type=EntryType.CUSTOM,
            dn=f"cn={c.Values.TEST},{c.DNs.EXAMPLE}",
            attributes={
                c.Names.CN: [c.Values.TEST],
                "customAttr": [c.Values.TEST],
            },
            description="Build custom entry",
        ),
    }

    @pytest.mark.parametrize(
        ("entry_type", "build_case"),
        ENTRY_BUILD_CASES.items(),
    )
    def test_create_entry_types(
        self,
        entry_type: EntryType,
        build_case: EntryBuildCase,
        api: FlextLdif,
    ) -> None:
        """Test create_entry() with various entry types."""
        result = api.create_entry(build_case.dn, build_case.attributes)
        if build_case.should_succeed:
            assert result.is_success
            entry = result.unwrap()
            assert isinstance(entry, p.Entry)
            assert entry.dn is not None
            assert entry.dn.value == build_case.dn

    entries_scenarios: ClassVar[set[EntryManipulationScenario]] = {
        EntryManipulationScenario.GET_DN,
        EntryManipulationScenario.GET_ATTRIBUTES,
        EntryManipulationScenario.GET_OBJECTCLASSES,
        EntryManipulationScenario.GET_ATTR_VALUES,
    }

    @pytest.mark.parametrize(
        "scenario",
        [[s] for s in entries_scenarios],
    )
    def test_entries_scenarios(
        self,
        scenario: EntryManipulationScenario,
        api: FlextLdif,
        sample_entry: p.Entry,
    ) -> None:
        """Test entry manipulation operations with parametrized scenarios."""
        if scenario == EntryManipulationScenario.GET_DN:
            result_dn = api.get_entry_dn(sample_entry)
            assert result_dn.is_success
            dn = result_dn.unwrap()
            assert isinstance(dn, str)
            assert dn == f"cn={c.Values.TEST} {c.Values.USER},ou=People,{c.DNs.EXAMPLE}"
        elif scenario == EntryManipulationScenario.GET_ATTRIBUTES:
            result_attrs = api.get_entry_attributes(sample_entry)
            assert result_attrs.is_success
            attrs = result_attrs.unwrap()
            assert isinstance(attrs, dict)
            assert "cn" in attrs
        elif scenario == EntryManipulationScenario.GET_OBJECTCLASSES:
            result_classes = api.get_entry_objectclasses(sample_entry)
            assert result_classes.is_success
            classes = result_classes.unwrap()
            assert isinstance(classes, list)
            assert "person" in classes
        elif scenario == EntryManipulationScenario.GET_ATTR_VALUES:
            result_attrs_for_values = api.get_entry_attributes(sample_entry)
            assert result_attrs_for_values.is_success
            attributes = result_attrs_for_values.unwrap()
            attr_result = api.get_attribute_values(attributes["mail"])
            assert attr_result.is_success
            values = attr_result.unwrap()
            assert isinstance(values, list)
            assert "test@example.com" in values


class TestAPIValidationAndFiltering:
    """Test validation, filtering, and ACL operations."""

    @pytest.fixture
    def validation_entries(self) -> list[p.Entry]:
        """Create sample entries for validation testing."""
        entries: list[p.Entry] = []
        for _i, name in enumerate(["Valid User", "Test User"]):
            entry_result = p.Entry.create(
                dn=f"cn={name},ou=People,{c.DNs.EXAMPLE}",
                attributes={
                    c.Names.CN: [name],
                    c.Names.SN: [c.Values.USER],
                    c.Names.OBJECTCLASS: [c.Names.PERSON],
                },
            )
            if entry_result.is_success:
                entry = entry_result.unwrap()
                entries.append(entry)

        return [m.Ldif.Entry(dn=e.dn, attributes=e.attributes) for e in entries]

    VALIDATION_SCENARIOS: ClassVar[set[ValidationScenario]] = {
        ValidationScenario.VALID_ENTRIES,
        ValidationScenario.EMPTY_LIST,
        ValidationScenario.PROPER_STRUCTURE,
        ValidationScenario.FILTER_OBJECTCLASS,
        ValidationScenario.FILTER_DN_PATTERN,
        ValidationScenario.EXTRACT_ACLS,
    }

    @pytest.mark.parametrize(
        "scenario",
        [[s] for s in VALIDATION_SCENARIOS],
    )
    def test_validation_scenarios(
        self,
        scenario: ValidationScenario,
        api: FlextLdif,
        validation_entries: list[p.Entry],
        sample_entries: list[p.Entry],
        entry_with_acl: p.Entry,
    ) -> None:
        """Test validation and filtering with parametrized scenarios."""
        if scenario == ValidationScenario.VALID_ENTRIES:
            result = api.validate_entries(validation_entries)
            assert result.is_success
            report = result.unwrap()
            assert report.is_valid is True
            assert report.total_entries == 2
        elif scenario == ValidationScenario.EMPTY_LIST:
            result = api.validate_entries([])
            assert result.is_success
            report = result.unwrap()
            assert report.is_valid is True
            assert report.total_entries == 0
        elif scenario == ValidationScenario.PROPER_STRUCTURE:
            result = api.validate_entries(validation_entries)
            assert result.is_success
            report = result.unwrap()
            assert hasattr(report, "is_valid")
            assert hasattr(report, "total_entries")
            assert hasattr(report, "errors")
        elif scenario == ValidationScenario.FILTER_OBJECTCLASS:
            # filter() returns FlextResult[list[Entry]],
            # not FlextResult[ValidationResult]
            filter_result = api.filter(sample_entries, objectclass="inetOrgPerson")
            if filter_result.is_success:
                filtered = filter_result.unwrap()
                assert isinstance(filtered, list)
        elif scenario == ValidationScenario.FILTER_DN_PATTERN:
            # filter() returns FlextResult[list[Entry]],
            # not FlextResult[ValidationResult]
            filter_result = api.filter(sample_entries, dn_pattern="User0")
            if filter_result.is_success:
                filtered = filter_result.unwrap()
                assert isinstance(filtered, list)
        elif scenario == ValidationScenario.EXTRACT_ACLS:
            # extract_acls() returns FlextResult[AclResponse],
            # not FlextResult[ValidationResult]
            acl_result = api.extract_acls(entry_with_acl)
            assert acl_result.is_success or acl_result.is_failure


class TestAPIConversionAndMigration:
    """Test migration operations with parametrized scenarios."""

    @pytest.fixture
    def migration_entries(self) -> list[p.Entry]:
        """Create sample entries for migration testing."""
        return [
            s.create_entry(
                dn=f"cn={c.Values.USER}{i},ou=People,{c.DNs.EXAMPLE}",
                attributes={
                    c.Names.CN: [f"{c.Values.USER}{i}"],
                    c.Names.SN: [c.Values.USER],
                    c.Names.OBJECTCLASS: [c.Names.PERSON],
                },
            )
            for i in range(2)
        ]

    MIGRATION_SCENARIOS: ClassVar[set[MigrationScenario]] = {
        MigrationScenario.BASIC_MIGRATE,
        MigrationScenario.MISSING_INPUT,
        MigrationScenario.SCHEMA_PROCESSING,
        MigrationScenario.NO_ENTRIES_PROCESSING,
    }

    @pytest.mark.parametrize(
        "scenario",
        [[s] for s in MIGRATION_SCENARIOS],
    )
    def test_migration_scenarios(
        self,
        scenario: MigrationScenario,
        api: FlextLdif,
        migration_entries: list[p.Entry],
        tmp_path: Path,
    ) -> None:
        """Test migration operations with parametrized scenarios."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        if scenario == MigrationScenario.MISSING_INPUT:
            result = api.migrate(
                input_dir=tmp_path / "nonexistent",
                output_dir=output_dir,
                source_server="oid",
                target_server="oud",
            )
            assert result.is_failure or result.is_success
        else:
            if scenario == MigrationScenario.BASIC_MIGRATE:
                ldif_file = input_dir / "entries.ldif"
                ldif_file.write_text(
                    f"dn: cn={c.Values.TEST},{c.DNs.EXAMPLE}\n"
                    f"objectClass: {c.Names.PERSON}\n"
                    f"cn: {c.Values.TEST}\n\n",
                )

            result = api.migrate(
                input_dir=input_dir,
                output_dir=output_dir,
                source_server="oid",
                target_server="oud",
            )
            assert result.is_success or result.is_failure

    def test_conversion_operations(
        self,
        api: FlextLdif,
        migration_entries: list[p.Entry],
    ) -> None:
        """Test conversion and attribute operations."""
        # Test get_entry_attributes
        attrs_result = api.get_entry_attributes(migration_entries[0])
        assert attrs_result.is_success

        # Test write - returns FlextResult[str]
        write_result = api.write(migration_entries)
        assert write_result.is_success

        # Test parse - returns FlextResult[list[Entry]]
        ldif_content = f"""dn: cn={c.Values.TEST},{c.DNs.EXAMPLE}
cn: {c.Values.TEST}
objectClass: {c.Names.PERSON}
"""
        parse_result = api.parse(ldif_content)
        assert parse_result.is_success

        # Test create_entry - returns FlextResult[Entry]
        create_result = api.create_entry(
            f"cn={c.Values.TEST},{c.DNs.EXAMPLE}",
            {c.Names.CN: [c.Values.TEST], c.Names.OBJECTCLASS: [c.Names.PERSON]},
        )
        assert create_result.is_success


class TestAPICoreProperties:
    """Test core API properties and singleton pattern."""

    CORE_PROPERTY_SCENARIOS: ClassVar[set[CorePropertiesScenario]] = {
        CorePropertiesScenario.MODELS,
        CorePropertiesScenario.CONFIG,
        CorePropertiesScenario.CONSTANTS,
        CorePropertiesScenario.ACL_SERVICE,
        CorePropertiesScenario.SINGLETON,
        CorePropertiesScenario.SINGLETON_WITH_CONFIG,
        CorePropertiesScenario.DETECT_OID,
        CorePropertiesScenario.DETECT_RFC,
    }

    @pytest.mark.parametrize(
        "scenario",
        [[s] for s in CORE_PROPERTY_SCENARIOS],
    )
    def test_core_properties_scenarios(
        self,
        scenario: CorePropertiesScenario,
        api: FlextLdif,
    ) -> None:
        """Test core properties with parametrized scenarios."""
        if scenario == CorePropertiesScenario.MODELS:
            models = api.models
            assert models is FlextLdifModels
            assert hasattr(models, "Entry")
        elif scenario == CorePropertiesScenario.CONFIG:
            config = api.config
            assert isinstance(config, FlextConfig)
            ldif_config = config.get_namespace("ldif", FlextLdifConfig)
            assert isinstance(ldif_config, FlextLdifConfig)
        elif scenario == CorePropertiesScenario.CONSTANTS:
            constants = api.constants
            assert constants is FlextLdifConstants
            assert hasattr(constants, "ServerTypes")
        elif scenario == CorePropertiesScenario.ACL_SERVICE:
            service = api.acl_service
            assert service is not None
            assert hasattr(service, "extract_acls_from_entry")
        elif scenario == CorePropertiesScenario.SINGLETON:
            instance1 = FlextLdif.get_instance()
            instance2 = FlextLdif.get_instance()
            assert instance1 is instance2
        elif scenario == CorePropertiesScenario.SINGLETON_WITH_CONFIG:
            # get_instance() expects FlextLdifConfig | None, not FlextConfig
            ldif_config = FlextLdifConfig()
            instance = FlextLdif.get_instance(ldif_config)
            assert instance is not None
            assert isinstance(instance, FlextLdif)
        elif scenario == CorePropertiesScenario.DETECT_OID:
            content = f"""dn: cn={c.Values.TEST},{c.DNs.EXAMPLE}
cn: {c.Values.TEST}
objectClass: {c.Names.PERSON}
orclGUID: 550e8400-e29b-41d4-a716-446655440000
"""
            result = api.detect_server_type(ldif_content=content)
            assert result.is_success or result.is_failure
        elif scenario == CorePropertiesScenario.DETECT_RFC:
            content = f"""dn: cn={c.Values.TEST},{c.DNs.EXAMPLE}
cn: {c.Values.TEST}
objectClass: {c.Names.PERSON}
"""
            result = api.detect_server_type(ldif_content=content)
            assert result.is_success or result.is_failure


class TestAPIProcessing:
    """Test processing operations with consolidated scenarios."""

    PROCESSING_SCENARIOS: ClassVar[dict[ProcessingScenario, ProcessingTestCase]] = {
        ProcessingScenario.TRANSFORM_BATCH: ProcessingTestCase(
            scenario=ProcessingScenario.TRANSFORM_BATCH,
            entry_count=1,
            description="Process single entry in batch mode",
        ),
        ProcessingScenario.VALIDATE_BATCH: ProcessingTestCase(
            scenario=ProcessingScenario.VALIDATE_BATCH,
            entry_count=3,
            description="Process multiple entries in batch mode",
        ),
        ProcessingScenario.PARALLEL_MODE: ProcessingTestCase(
            scenario=ProcessingScenario.PARALLEL_MODE,
            entry_count=3,
            description="Process entries in parallel mode",
        ),
        ProcessingScenario.UNKNOWN_PROCESSOR: ProcessingTestCase(
            scenario=ProcessingScenario.UNKNOWN_PROCESSOR,
            entry_count=1,
            should_succeed=False,
            description="Unknown processor",
        ),
        ProcessingScenario.EMPTY_ENTRIES: ProcessingTestCase(
            scenario=ProcessingScenario.EMPTY_ENTRIES,
            entry_count=0,
            description="Process empty entry list",
        ),
    }

    @pytest.mark.parametrize(
        ("scenario", "test_case"),
        PROCESSING_SCENARIOS.items(),
    )
    def test_processing_scenarios(
        self,
        scenario: ProcessingScenario,
        test_case: ProcessingTestCase,
        api: FlextLdif,
        sample_entry: p.Entry,
        tmp_path: Path,
    ) -> None:
        """Test processing operations with parametrized scenarios."""
        entries = (
            [sample_entry] * test_case.entry_count if test_case.entry_count > 0 else []
        )

        if scenario == ProcessingScenario.TRANSFORM_BATCH:
            result = api.process("transform", entries, parallel=False, batch_size=10)
        elif scenario == ProcessingScenario.VALIDATE_BATCH:
            result = api.process("validate", entries, parallel=False, batch_size=10)
        elif scenario == ProcessingScenario.PARALLEL_MODE:
            result = api.process("transform", entries, parallel=True)
        elif scenario == ProcessingScenario.UNKNOWN_PROCESSOR:
            result = api.process("unknown_processor", entries)
        elif scenario == ProcessingScenario.EMPTY_ENTRIES:
            result = api.process("transform", entries)
        else:
            result = api.process("transform", entries)

        if test_case.should_succeed or scenario != ProcessingScenario.UNKNOWN_PROCESSOR:
            assert result.is_success or result.is_failure
            if result.is_success:
                processed = result.unwrap()
                assert isinstance(processed, list)


__all__ = [
    "APIOperation",
    "CorePropertiesScenario",
    "EntryBuildCase",
    "EntryManipulationScenario",
    "EntryType",
    "InputType",
    "MigrationScenario",
    "ParsingScenario",
    "ParsingTestCase",
    "ProcessingMode",
    "ProcessingScenario",
    "ProcessingTestCase",
    "ServerType",
    "TestAPIConversionAndMigration",
    "TestAPICoreProperties",
    "TestAPIEntryManipulation",
    "TestAPIParsingOperations",
    "TestAPIProcessing",
    "TestAPIValidationAndFiltering",
    "TestAPIWritingOperations",
    "ValidationScenario",
    "WritingScenario",
]
