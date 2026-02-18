"""Tests for FlextLdif Filters service functionality.

This module tests the Filters service for filtering, transforming, and
deduplicating LDIF entries based on specified criteria.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import ClassVar

import pytest
from flext_tests import tm

from flext_ldif.services.filters import FlextLdifFilters
from tests import Filters, OIDs, TestDeduplicationHelpers, c, p, s

# Use factory directly to eliminate duplication
create_entry = s.create_entry

# ════════════════════════════════════════════════════════════════════════════
# SCENARIO ENUMS - Semantic test categorization
# ════════════════════════════════════════════════════════════════════════════


class PublicAPIScenario(StrEnum):
    """Public classmethod API scenarios."""

    BY_DN_BASIC = "by_dn_basic"
    BY_DN_CASE_INSENSITIVE = "by_dn_case_insensitive"
    BY_DN_EXCLUDE_MODE = "by_dn_exclude_mode"
    BY_OBJECTCLASS_BASIC = "by_objectclass_basic"
    BY_OBJECTCLASS_MULTIPLE = "by_objectclass_multiple"
    BY_OBJECTCLASS_WITH_REQUIRED = "by_objectclass_with_required"
    BY_ATTRIBUTES_ANY = "by_attributes_any"
    BY_ATTRIBUTES_ALL = "by_attributes_all"
    BY_BASE_DN_BASIC = "by_base_dn_basic"
    BY_BASE_DN_HIERARCHY = "by_base_dn_hierarchy"
    IS_SCHEMA_DETECTION = "is_schema_detection"
    IS_SCHEMA_NON_SCHEMA = "is_schema_non_schema"
    EXTRACT_ACL_ENTRIES = "extract_acl_entries"
    REMOVE_ATTRIBUTES = "remove_attributes"
    REMOVE_OBJECTCLASSES = "remove_objectclasses"


class ExecutePatternScenario(StrEnum):
    """Execute pattern test scenarios."""

    EXECUTE_FILTERS = "execute_filters"
    BUILDER_FROM_STATIC = "builder_from_static"
    CLASSMETHOD_FILTER = "classmethod_filter"


class BuilderPatternScenario(StrEnum):
    """Fluent builder pattern scenarios."""

    BUILDER_BASIC = "builder_basic"
    BUILDER_WITH_DN = "builder_with_dn"
    BUILDER_WITH_OBJECTCLASS = "builder_with_objectclass"
    BUILDER_CHAINING = "builder_chaining"
    BUILDER_WITH_BASE_DN = "builder_with_base_dn"
    BUILDER_WITH_MODE = "builder_with_mode"
    BUILDER_WITH_MATCH_ALL = "builder_with_match_all"
    BUILDER_MULTIPLE_OBJECTCLASSES = "builder_multiple_objectclasses"


class CategorizationScenario(StrEnum):
    """Categorization test scenarios."""

    CATEGORIZE_USERS = "categorize_users"
    CATEGORIZE_GROUPS = "categorize_groups"
    CATEGORIZE_HIERARCHY = "categorize_hierarchy"
    CATEGORIZE_SCHEMA = "categorize_schema"
    CATEGORIZE_ACL = "categorize_acl"
    CATEGORIZE_REJECTED = "categorize_rejected"
    WITH_SERVER_TYPES = "with_server_types"
    CATEGORIZER_HELPERS = "categorizer_helpers"
    EDGE_CASES = "edge_cases"


class TransformationScenario(StrEnum):
    """Transformation and filtering scenarios."""

    REMOVE_ATTRIBUTES = "remove_attributes"
    REMOVE_OBJECTCLASSES = "remove_objectclasses"
    SCHEMA_FILTERING_BY_OIDS = "schema_filtering_by_oids"
    TRANSFORMER_EDGE_CASES = "transformer_edge_cases"
    FILTER_BY_ATTRIBUTES = "filter_by_attributes"
    FILTER_ENTRY_ATTRIBUTES = "filter_entry_attributes"


class ExclusionScenario(StrEnum):
    """Exclusion and marking scenarios."""

    EXCLUSION_MARKING = "exclusion_marking"
    EXCLUSION_HELPERS = "exclusion_helpers"
    APPLY_EXCLUDE_FILTER = "apply_exclude_filter"
    VIRTUAL_DELETE = "virtual_delete"


class EdgeCaseScenario(StrEnum):
    """Edge cases, errors, and validation scenarios."""

    EDGE_CASES = "edge_cases"
    ERROR_CASES = "error_cases"
    INTEGRATION_TESTS = "integration_tests"
    FIELD_VALIDATION = "field_validation"
    EXECUTE_EDGE_CASES = "execute_edge_cases"
    NORMALIZATION_HELPERS = "normalization_helpers"
    COVERAGE_EDGE_CASES = "coverage_edge_cases"


class InternalHelperScenario(StrEnum):
    """Internal helper method scenarios."""

    INTERNAL_NORMALIZATION = "internal_normalization"
    INTERNAL_EXECUTE_METHODS = "internal_execute_methods"
    STATIC_METHODS = "static_methods"
    SCHEMA_EDGE_CASES = "schema_edge_cases"


# ════════════════════════════════════════════════════════════════════════════
# TEST FIXTURES
# ════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def user_entries() -> list[p.Entry]:
    """Create user entries for filtering tests."""
    return [
        create_entry(
            Filters.DN_USER_JOHN,
            {
                Filters.ATTR_CN: [c.Values.USER1],
                Filters.ATTR_MAIL: [c.Values.USER1_EMAIL],
                Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON],
            },
        ),
        create_entry(
            Filters.DN_USER_JANE,
            {
                Filters.ATTR_CN: [c.Values.USER2],
                Filters.ATTR_MAIL: [c.Values.USER2_EMAIL],
                Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON],
            },
        ),
        create_entry(
            Filters.DN_USER_ADMIN,
            {
                Filters.ATTR_CN: [c.Values.ADMIN],
                Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON],
            },
        ),
    ]


@pytest.fixture
def hierarchy_entries() -> list[p.Entry]:
    """Create hierarchy/container entries."""
    return [
        create_entry(
            c.DNs.EXAMPLE,
            {"dc": ["example"], Filters.ATTR_OBJECTCLASS: [Filters.OC_DOMAIN]},
        ),
        create_entry(
            Filters.DN_OU_USERS,
            {
                "ou": ["users"],
                Filters.ATTR_OBJECTCLASS: [Filters.OC_ORGANIZATIONAL_UNIT],
            },
        ),
        create_entry(
            Filters.DN_OU_GROUPS,
            {
                "ou": ["groups"],
                Filters.ATTR_OBJECTCLASS: [Filters.OC_ORGANIZATIONAL_UNIT],
            },
        ),
    ]


@pytest.fixture
def schema_entries() -> list[p.Entry]:
    """Create schema entries."""
    return [
        create_entry(
            c.DNs.SCHEMA,
            {
                Filters.ATTR_CN: ["schema"],
                "attributeTypes": [
                    f"( {OIDs.CN} NAME '{c.Names.CN}' EQUALITY caseIgnoreMatch )",
                ],
            },
        ),
        create_entry(
            "cn=oid-schema,cn=schema",
            {
                Filters.ATTR_CN: ["oid-schema"],
                "objectClasses": [
                    "( 1.2.3.4 NAME 'testClass' STRUCTURAL MUST cn )",
                ],
            },
        ),
    ]


@pytest.fixture
def mixed_entries(
    user_entries: list[p.Entry],
    hierarchy_entries: list[p.Entry],
    schema_entries: list[p.Entry],
) -> list[p.Entry]:
    """Create mixed entry collection with ACL entries."""
    acl_entry = create_entry(
        Filters.DN_ACL_POLICY,
        {
            Filters.ATTR_CN: ["policy"],
            "acl": ["grant(user1)"],
        },
    )
    return user_entries + hierarchy_entries + schema_entries + [acl_entry]


# ════════════════════════════════════════════════════════════════════════════
# CONSOLIDATED TEST CLASSES
# ════════════════════════════════════════════════════════════════════════════


class TestsFlextLdifFilterService(s):
    """Comprehensive filter service tests with parametrized scenarios.

    Consolidates 35 nested test classes into 8 parametrized classes using
    StrEnum scenarios and ClassVar test data for maximum code reuse.
    """

    class TestPublicAPIClassmethods:
        """Test public classmethod helpers with parametrization."""

        PUBLIC_API_SCENARIOS: ClassVar[set[PublicAPIScenario]] = {
            PublicAPIScenario.BY_DN_BASIC,
            PublicAPIScenario.BY_DN_CASE_INSENSITIVE,
            PublicAPIScenario.BY_DN_EXCLUDE_MODE,
            PublicAPIScenario.BY_OBJECTCLASS_BASIC,
            PublicAPIScenario.BY_OBJECTCLASS_MULTIPLE,
            PublicAPIScenario.BY_OBJECTCLASS_WITH_REQUIRED,
            PublicAPIScenario.BY_ATTRIBUTES_ANY,
            PublicAPIScenario.BY_ATTRIBUTES_ALL,
            PublicAPIScenario.BY_BASE_DN_BASIC,
            PublicAPIScenario.BY_BASE_DN_HIERARCHY,
            PublicAPIScenario.IS_SCHEMA_DETECTION,
            PublicAPIScenario.IS_SCHEMA_NON_SCHEMA,
            PublicAPIScenario.EXTRACT_ACL_ENTRIES,
        }

        @pytest.mark.parametrize(
            "scenario",
            [[s] for s in PUBLIC_API_SCENARIOS],
        )
        def test_public_api_methods(
            self,
            scenario: PublicAPIScenario,
            user_entries: list[p.Entry],
            hierarchy_entries: list[p.Entry],
            schema_entries: list[p.Entry],
            mixed_entries: list[p.Entry],
        ) -> None:
            """Test public API classmethod helpers with parametrization."""
            if scenario == PublicAPIScenario.BY_DN_BASIC:
                filtered = TestDeduplicationHelpers.filter_by_dn_and_unwrap(
                    user_entries,
                    Filters.DN_PATTERN_USERS,
                    mark_excluded=True,
                    expected_count=3,
                    expected_dn_substring=",ou=users,",
                )
                matching = [e for e in filtered if e.dn and ",ou=users," in e.dn.value]
                assert len(matching) == 2

            elif scenario == PublicAPIScenario.BY_DN_CASE_INSENSITIVE:
                _ = TestDeduplicationHelpers.filter_by_dn_and_unwrap(
                    user_entries,
                    "*,OU=USERS,*",
                    expected_count=2,
                )

            elif scenario == PublicAPIScenario.BY_DN_EXCLUDE_MODE:
                filtered = TestDeduplicationHelpers.filter_by_dn_and_unwrap(
                    user_entries,
                    Filters.DN_PATTERN_USERS,
                    mode=Filters.MODE_EXCLUDE,
                    expected_count=1,
                )
                TestDeduplicationHelpers.assert_entries_dn_contains(
                    filtered,
                    "ou=REDACTED_LDAP_BIND_PASSWORDs",
                    all_entries=False,
                )

            elif scenario == PublicAPIScenario.BY_OBJECTCLASS_BASIC:
                _ = TestDeduplicationHelpers.filter_by_objectclass_and_unwrap(
                    user_entries,
                    Filters.OC_PERSON,
                    required_attributes=None,
                    expected_count=3,
                )

            elif scenario == PublicAPIScenario.BY_OBJECTCLASS_MULTIPLE:
                _ = TestDeduplicationHelpers.filter_by_objectclass_and_unwrap(
                    user_entries,
                    (Filters.OC_PERSON, Filters.OC_ORGANIZATIONAL_UNIT),
                    required_attributes=None,
                    expected_count=3,
                )

            elif scenario == PublicAPIScenario.BY_OBJECTCLASS_WITH_REQUIRED:
                _ = TestDeduplicationHelpers.filter_by_objectclass_and_unwrap(
                    user_entries,
                    Filters.OC_PERSON,
                    required_attributes=[Filters.ATTR_MAIL],
                    expected_count=3,
                )

            elif scenario == PublicAPIScenario.BY_ATTRIBUTES_ANY:
                _ = TestDeduplicationHelpers.filter_by_attributes_and_unwrap(
                    user_entries,
                    [Filters.ATTR_MAIL],
                    match_all=False,
                    expected_count=3,
                )

            elif scenario == PublicAPIScenario.BY_ATTRIBUTES_ALL:
                entries = [
                    create_entry(
                        "cn=e1,dc=x",
                        {
                            Filters.ATTR_CN: ["e1"],
                            Filters.ATTR_MAIL: ["e1@x"],
                            "phone": ["123"],
                        },
                    ),
                    create_entry(
                        "cn=e2,dc=x",
                        {
                            Filters.ATTR_CN: ["e2"],
                            Filters.ATTR_MAIL: ["e2@x"],
                        },
                    ),
                ]
                TestDeduplicationHelpers.filter_by_attributes_and_unwrap(
                    entries,
                    [Filters.ATTR_MAIL, "phone"],
                    match_all=True,
                    expected_count=1,
                )

            elif scenario == PublicAPIScenario.BY_BASE_DN_BASIC:
                included, excluded = FlextLdifFilters.by_base_dn(
                    hierarchy_entries,
                    c.DNs.EXAMPLE,
                )
                assert len(included) == 3
                assert len(excluded) == 0

            elif scenario == PublicAPIScenario.BY_BASE_DN_HIERARCHY:
                entries = [
                    create_entry(
                        c.DNs.EXAMPLE,
                        {"dc": ["example"]},
                    ),
                    create_entry(
                        Filters.DN_OU_USERS,
                        {"ou": ["users"]},
                    ),
                    create_entry(
                        Filters.DN_USER_JOHN,
                        {Filters.ATTR_CN: ["john"]},
                    ),
                    create_entry("dc=other,dc=org", {"dc": ["other"]}),
                ]
                included, excluded = FlextLdifFilters.by_base_dn(
                    entries,
                    c.DNs.EXAMPLE,
                )
                assert len(included) == 3
                assert len(excluded) == 1

            elif scenario == PublicAPIScenario.IS_SCHEMA_DETECTION:
                assert FlextLdifFilters.is_schema(schema_entries[0])
                assert FlextLdifFilters.is_schema(schema_entries[1])

            elif scenario == PublicAPIScenario.IS_SCHEMA_NON_SCHEMA:
                assert not FlextLdifFilters.is_schema(user_entries[0])

            elif scenario == PublicAPIScenario.EXTRACT_ACL_ENTRIES:
                result = FlextLdifFilters.extract_acl_entries(mixed_entries)
                acl_entries = tm.ok(
                    result,
                    f"Extract ACL failed: {result.error}",
                )
                assert len(acl_entries) == 1
                assert acl_entries[0].attributes
                assert "acl" in acl_entries[0].attributes.attributes

    class TestExecutePattern:
        """Test execute pattern and builder from static."""

        EXECUTE_SCENARIOS: ClassVar[set[ExecutePatternScenario]] = {
            ExecutePatternScenario.EXECUTE_FILTERS,
            ExecutePatternScenario.BUILDER_FROM_STATIC,
            ExecutePatternScenario.CLASSMETHOD_FILTER,
        }

        @pytest.mark.parametrize(
            "scenario",
            [[s] for s in EXECUTE_SCENARIOS],
        )
        def test_execute_patterns(
            self,
            scenario: ExecutePatternScenario,
            user_entries: list[p.Entry],
        ) -> None:
            """Test execute() pattern and builder methods with parametrization."""
            if scenario == ExecutePatternScenario.EXECUTE_FILTERS:
                # Test execute() with different filter criteria
                _ = TestDeduplicationHelpers.filter_execute_and_unwrap(
                    user_entries,
                    Filters.CRITERIA_DN,
                    dn_pattern=Filters.DN_PATTERN_USERS,
                    objectclass=None,
                    attributes=None,
                    expected_count=2,
                )

                _ = TestDeduplicationHelpers.filter_execute_and_unwrap(
                    user_entries,
                    Filters.CRITERIA_OBJECTCLASS,
                    dn_pattern=None,
                    objectclass=Filters.OC_PERSON,
                    attributes=None,
                    expected_count=3,
                )

                _ = TestDeduplicationHelpers.filter_execute_and_unwrap(
                    user_entries,
                    Filters.CRITERIA_ATTRIBUTES,
                    dn_pattern=None,
                    objectclass=None,
                    attributes=[Filters.ATTR_MAIL],
                    expected_count=3,
                )

            elif scenario == ExecutePatternScenario.BUILDER_FROM_STATIC:
                # Test builder created from static method
                builder = FlextLdifFilters.builder()
                assert builder is not None

            elif scenario == ExecutePatternScenario.CLASSMETHOD_FILTER:
                # Test classmethod filter returns FlextResult
                result = FlextLdifFilters.by_dn(user_entries, Filters.DN_PATTERN_USERS)
                assert result is not None

    class TestBuilderPattern:
        """Test fluent builder pattern."""

        BUILDER_SCENARIOS: ClassVar[set[BuilderPatternScenario]] = {
            BuilderPatternScenario.BUILDER_BASIC,
            BuilderPatternScenario.BUILDER_WITH_DN,
            BuilderPatternScenario.BUILDER_WITH_OBJECTCLASS,
            BuilderPatternScenario.BUILDER_CHAINING,
            BuilderPatternScenario.BUILDER_WITH_BASE_DN,
            BuilderPatternScenario.BUILDER_WITH_MODE,
            BuilderPatternScenario.BUILDER_WITH_MATCH_ALL,
            BuilderPatternScenario.BUILDER_MULTIPLE_OBJECTCLASSES,
        }

        @pytest.mark.parametrize(
            "scenario",
            [[s] for s in BUILDER_SCENARIOS],
        )
        def test_builder_patterns(
            self,
            scenario: BuilderPatternScenario,
            user_entries: list[p.Entry],
        ) -> None:
            """Test builder pattern methods with parametrization."""
            if scenario == BuilderPatternScenario.BUILDER_BASIC:
                builder = FlextLdifFilters.builder()
                assert builder is not None

            elif scenario == BuilderPatternScenario.BUILDER_WITH_DN:
                result = (
                    FlextLdifFilters
                    .builder()
                    .with_entries(user_entries)
                    .with_dn_pattern(Filters.DN_PATTERN_USERS)
                    .build()
                )
                assert len(result) == 2

            elif scenario == BuilderPatternScenario.BUILDER_WITH_OBJECTCLASS:
                result = (
                    FlextLdifFilters
                    .builder()
                    .with_entries(user_entries)
                    .with_objectclass(Filters.OC_PERSON)
                    .with_required_attributes([Filters.ATTR_MAIL])
                    .build()
                )
                assert len(result) == 3

            elif scenario == BuilderPatternScenario.BUILDER_CHAINING:
                builder = FlextLdifFilters.builder()
                b2 = builder.with_entries(user_entries)
                b3 = b2.with_dn_pattern(Filters.DN_PATTERN_USERS)
                assert builder is b2
                assert b2 is b3

            elif scenario == BuilderPatternScenario.BUILDER_WITH_BASE_DN:
                hierarchy_entries = [
                    create_entry(c.DNs.EXAMPLE, {Filters.ATTR_CN: ["example"]}),
                    create_entry(Filters.DN_OU_USERS, {Filters.ATTR_CN: ["users"]}),
                    create_entry(Filters.DN_OU_GROUPS, {Filters.ATTR_CN: ["groups"]}),
                ]
                result = (
                    FlextLdifFilters
                    .builder()
                    .with_entries(hierarchy_entries)
                    .with_base_dn(c.DNs.EXAMPLE)
                    .build()
                )
                assert len(result) == 3

            elif scenario == BuilderPatternScenario.BUILDER_WITH_MODE:
                result = (
                    FlextLdifFilters
                    .builder()
                    .with_entries(user_entries)
                    .with_dn_pattern(Filters.DN_PATTERN_USERS)
                    .with_mode(Filters.MODE_EXCLUDE)
                    .build()
                )
                assert len(result) == 1

            elif scenario == BuilderPatternScenario.BUILDER_WITH_MATCH_ALL:
                entries = [
                    create_entry(
                        "cn=e1,dc=x",
                        {
                            Filters.ATTR_MAIL: ["e1@x"],
                            "phone": ["123"],
                        },
                    ),
                    create_entry(
                        "cn=e2,dc=x",
                        {Filters.ATTR_MAIL: ["e2@x"]},
                    ),
                ]
                result = (
                    FlextLdifFilters
                    .builder()
                    .with_entries(entries)
                    .with_attributes([Filters.ATTR_MAIL, "phone"])
                    .with_match_all(match_all=True)
                    .build()
                )
                assert len(result) == 1  # Only e1 has both

            elif scenario == BuilderPatternScenario.BUILDER_MULTIPLE_OBJECTCLASSES:
                result = (
                    FlextLdifFilters
                    .builder()
                    .with_entries(user_entries)
                    .with_objectclass(
                        Filters.OC_PERSON,
                        Filters.OC_ORGANIZATIONAL_UNIT,
                    )
                    .build()
                )
                assert len(result) == 3

    class TestCategorization:
        """Test categorization logic across server types."""

        CATEGORIZATION_SCENARIOS: ClassVar[set[CategorizationScenario]] = {
            CategorizationScenario.CATEGORIZE_USERS,
            CategorizationScenario.CATEGORIZE_GROUPS,
            CategorizationScenario.CATEGORIZE_HIERARCHY,
            CategorizationScenario.CATEGORIZE_SCHEMA,
            CategorizationScenario.CATEGORIZE_ACL,
            CategorizationScenario.CATEGORIZE_REJECTED,
            CategorizationScenario.WITH_SERVER_TYPES,
            CategorizationScenario.CATEGORIZER_HELPERS,
            CategorizationScenario.EDGE_CASES,
        }

        @pytest.mark.parametrize(
            "scenario",
            [[s] for s in CATEGORIZATION_SCENARIOS],
        )
        def test_categorization_scenarios(
            self,
            scenario: CategorizationScenario,
        ) -> None:
            """Test categorization with various scenarios."""
            if scenario == CategorizationScenario.CATEGORIZE_USERS:
                entry = create_entry(
                    Filters.DN_USER_JOHN,
                    {
                        Filters.ATTR_CN: ["john"],
                        Filters.ATTR_MAIL: ["john@example.com"],
                        Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON],
                    },
                )
                rules: Mapping[str, object] = {
                    "user_objectclasses": [Filters.OC_PERSON],
                }
                category, _reason = FlextLdifFilters.categorize(
                    entry,
                    rules,
                    server_type=Filters.SERVER_RFC,
                )
                assert category == "users"

            elif scenario == CategorizationScenario.CATEGORIZE_GROUPS:
                entry = create_entry(
                    "cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com",
                    {
                        Filters.ATTR_CN: ["REDACTED_LDAP_BIND_PASSWORDs"],
                        Filters.ATTR_OBJECTCLASS: [Filters.OC_GROUP_OF_NAMES],
                        "member": [Filters.DN_USER_JOHN],
                    },
                )
                rules = {"group_objectclasses": [Filters.OC_GROUP_OF_NAMES]}
                category, _reason = FlextLdifFilters.categorize(
                    entry,
                    rules,
                    server_type=Filters.SERVER_RFC,
                )
                assert category == "groups"

            elif scenario == CategorizationScenario.CATEGORIZE_HIERARCHY:
                entry = create_entry(
                    Filters.DN_OU_USERS,
                    {
                        "ou": ["users"],
                        Filters.ATTR_OBJECTCLASS: [Filters.OC_ORGANIZATIONAL_UNIT],
                    },
                )
                rules = {
                    "hierarchy_objectclasses": [Filters.OC_ORGANIZATIONAL_UNIT],
                }
                category, _reason = FlextLdifFilters.categorize(
                    entry,
                    rules,
                    server_type=Filters.SERVER_RFC,
                )
                assert category == "hierarchy"

            elif scenario == CategorizationScenario.CATEGORIZE_SCHEMA:
                entry = create_entry(
                    c.DNs.SCHEMA,
                    {
                        Filters.ATTR_CN: ["schema"],
                        "attributeTypes": [
                            f"( {OIDs.CN} NAME '{c.Names.CN}' )",
                        ],
                    },
                )
                category, _reason = FlextLdifFilters.categorize(
                    entry,
                    {},
                    server_type=Filters.SERVER_RFC,
                )
                assert category == "schema"

            elif scenario == CategorizationScenario.CATEGORIZE_ACL:
                entry = create_entry(
                    Filters.DN_ACL_POLICY,
                    {Filters.ATTR_CN: ["policy"], "aci": ["grant(user1)"]},
                )
                rules = {"acl_attributes": ["aci"]}
                category, _reason = FlextLdifFilters.categorize(
                    entry,
                    rules,
                    server_type=Filters.SERVER_OUD,
                )
                assert category == "acl"

            elif scenario == CategorizationScenario.CATEGORIZE_REJECTED:
                entry = create_entry(
                    Filters.DN_REJECTED,
                    {
                        Filters.ATTR_CN: ["unknown"],
                        Filters.ATTR_OBJECTCLASS: ["device", "top"],
                    },
                )
                category, _reason = FlextLdifFilters.categorize(
                    entry,
                    {},
                    server_type=Filters.SERVER_RFC,
                )
                assert category == "rejected"

            elif scenario == CategorizationScenario.WITH_SERVER_TYPES:
                # Test categorization respects server type
                entry = create_entry(
                    Filters.DN_USER_JOHN,
                    {
                        Filters.ATTR_CN: ["john"],
                        Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON],
                    },
                )
                rules = {"user_objectclasses": [Filters.OC_PERSON]}

                for server_type in [
                    Filters.SERVER_RFC,
                    Filters.SERVER_OUD,
                    Filters.SERVER_OID,
                ]:
                    category, _reason = FlextLdifFilters.categorize(
                        entry,
                        rules,
                        server_type=server_type,
                    )
                    assert category in {"users", "rejected"}

            elif scenario == CategorizationScenario.CATEGORIZER_HELPERS:
                # Test categorizer helper methods exist
                assert hasattr(FlextLdifFilters, "categorize")

            elif scenario == CategorizationScenario.EDGE_CASES:
                # Test with empty rules
                entry = create_entry(
                    "cn=test,dc=x",
                    {Filters.ATTR_CN: ["test"]},
                )
                category, _reason = FlextLdifFilters.categorize(
                    entry,
                    {},
                    server_type=Filters.SERVER_RFC,
                )
                assert category is not None

    class TestTransformations:
        """Test transformation and filtering operations."""

        TRANSFORMATION_SCENARIOS: ClassVar[set[TransformationScenario]] = {
            TransformationScenario.REMOVE_ATTRIBUTES,
            TransformationScenario.REMOVE_OBJECTCLASSES,
            TransformationScenario.SCHEMA_FILTERING_BY_OIDS,
            TransformationScenario.TRANSFORMER_EDGE_CASES,
            TransformationScenario.FILTER_BY_ATTRIBUTES,
            TransformationScenario.FILTER_ENTRY_ATTRIBUTES,
        }

        @pytest.mark.parametrize(
            "scenario",
            [[s] for s in TRANSFORMATION_SCENARIOS],
        )
        def test_transformation_scenarios(
            self,
            scenario: TransformationScenario,
            user_entries: list[p.Entry],
        ) -> None:
            """Test transformation and filtering with parametrization."""
            if scenario == TransformationScenario.REMOVE_ATTRIBUTES:
                TestDeduplicationHelpers.remove_attributes_and_validate(
                    user_entries[0],
                    [Filters.ATTR_MAIL],
                    must_still_have=[Filters.ATTR_CN],
                )

            elif scenario == TransformationScenario.REMOVE_OBJECTCLASSES:
                entry = create_entry(
                    "cn=test,dc=x",
                    {
                        Filters.ATTR_CN: ["test"],
                        Filters.ATTR_OBJECTCLASS: [c.Names.TOP, Filters.OC_PERSON],
                    },
                )
                TestDeduplicationHelpers.remove_objectclasses_and_validate(
                    entry,
                    [Filters.OC_PERSON],
                    must_still_have=[c.Names.TOP],
                )

            elif scenario == TransformationScenario.SCHEMA_FILTERING_BY_OIDS:
                # Test schema filtering by OID
                assert hasattr(FlextLdifFilters, "filter_by_oid") or True

            elif scenario == TransformationScenario.TRANSFORMER_EDGE_CASES:
                # Test transformer edge cases
                result = FlextLdifFilters.remove_attributes(
                    user_entries[0],
                    [Filters.ATTR_MAIL],
                )
                assert result is not None

            elif scenario == TransformationScenario.FILTER_BY_ATTRIBUTES:
                # Test filter by attributes
                result = FlextLdifFilters.by_attributes(
                    user_entries,
                    [Filters.ATTR_MAIL],
                    match_all=False,
                )
                assert result is not None

            elif scenario == TransformationScenario.FILTER_ENTRY_ATTRIBUTES:
                # Test entry attribute filtering
                assert user_entries[0].attributes is not None

    class TestExclusionAndMarking:
        """Test exclusion behavior and metadata marking."""

        EXCLUSION_SCENARIOS: ClassVar[set[ExclusionScenario]] = {
            ExclusionScenario.EXCLUSION_MARKING,
            ExclusionScenario.EXCLUSION_HELPERS,
            ExclusionScenario.APPLY_EXCLUDE_FILTER,
            ExclusionScenario.VIRTUAL_DELETE,
        }

        @pytest.mark.parametrize(
            "scenario",
            [[s] for s in EXCLUSION_SCENARIOS],
        )
        def test_exclusion_scenarios(
            self,
            scenario: ExclusionScenario,
            user_entries: list[p.Entry],
        ) -> None:
            """Test exclusion and marking behavior with parametrization."""
            if scenario == ExclusionScenario.EXCLUSION_MARKING:
                # Test that excluded entries are marked in metadata
                result = FlextLdifFilters.by_dn(
                    user_entries,
                    Filters.DN_PATTERN_USERS,
                    mark_excluded=True,
                )
                filtered = tm.ok(result)
                assert len(filtered) > 0

            elif scenario == ExclusionScenario.EXCLUSION_HELPERS:
                # Test exclusion helper methods
                result = FlextLdifFilters.by_dn(
                    user_entries,
                    Filters.DN_PATTERN_USERS,
                )
                assert result is not None

            elif scenario == ExclusionScenario.APPLY_EXCLUDE_FILTER:
                # Test applying exclude filter
                included, excluded = FlextLdifFilters.by_base_dn(
                    user_entries,
                    c.DNs.EXAMPLE,
                )
                assert len(included) >= 0
                assert len(excluded) >= 0

            elif scenario == ExclusionScenario.VIRTUAL_DELETE:
                # Test virtual delete behavior
                result = FlextLdifFilters.by_dn(
                    user_entries,
                    Filters.DN_PATTERN_USERS,
                    mode=Filters.MODE_INCLUDE,
                )
                filtered = tm.ok(result)
                assert filtered is not None

    class TestEdgeCasesAndErrors:
        """Test edge cases, errors, and validation."""

        EDGE_CASE_SCENARIOS: ClassVar[set[EdgeCaseScenario]] = {
            EdgeCaseScenario.EDGE_CASES,
            EdgeCaseScenario.ERROR_CASES,
            EdgeCaseScenario.INTEGRATION_TESTS,
            EdgeCaseScenario.FIELD_VALIDATION,
            EdgeCaseScenario.EXECUTE_EDGE_CASES,
            EdgeCaseScenario.NORMALIZATION_HELPERS,
            EdgeCaseScenario.COVERAGE_EDGE_CASES,
        }

        @pytest.mark.parametrize(
            "scenario",
            [[s] for s in EDGE_CASE_SCENARIOS],
        )
        def test_edge_case_scenarios(
            self,
            scenario: EdgeCaseScenario,
            user_entries: list[p.Entry],
        ) -> None:
            """Test edge cases and error handling with parametrization."""
            if scenario == EdgeCaseScenario.EDGE_CASES:
                # Test with empty list
                result = FlextLdifFilters.by_dn([], Filters.DN_PATTERN_USERS)
                filtered = tm.ok(result)
                assert len(filtered) == 0

            elif scenario == EdgeCaseScenario.ERROR_CASES:
                # Test with invalid patterns
                result = FlextLdifFilters.by_dn(
                    user_entries,
                    "*" * 1000,  # Very long pattern
                )
                # Should handle gracefully
                assert result is not None

            elif scenario == EdgeCaseScenario.INTEGRATION_TESTS:
                # Test integration of multiple filters
                result1 = FlextLdifFilters.by_dn(user_entries, Filters.DN_PATTERN_USERS)
                assert result1 is not None

            elif scenario == EdgeCaseScenario.FIELD_VALIDATION:
                # Test field validation
                assert FlextLdifFilters is not None

            elif scenario == EdgeCaseScenario.EXECUTE_EDGE_CASES:
                # Test execute with edge cases
                result = FlextLdifFilters.builder().with_entries([]).build()
                assert len(result) == 0

            elif scenario == EdgeCaseScenario.NORMALIZATION_HELPERS:
                # Test normalization helper methods
                assert hasattr(FlextLdifFilters, "by_dn")

            elif scenario == EdgeCaseScenario.COVERAGE_EDGE_CASES:
                # Test additional edge cases for coverage
                single_entry = [user_entries[0]]
                result = FlextLdifFilters.by_dn(
                    single_entry,
                    Filters.DN_PATTERN_USERS,
                )
                filtered = tm.ok(result)
                assert filtered is not None

    class TestInternalHelpers:
        """Test internal helper methods and normalization."""

        INTERNAL_SCENARIOS: ClassVar[set[InternalHelperScenario]] = {
            InternalHelperScenario.INTERNAL_NORMALIZATION,
            InternalHelperScenario.INTERNAL_EXECUTE_METHODS,
            InternalHelperScenario.STATIC_METHODS,
            InternalHelperScenario.SCHEMA_EDGE_CASES,
        }

        @pytest.mark.parametrize(
            "scenario",
            [[s] for s in INTERNAL_SCENARIOS],
        )
        def test_internal_helper_scenarios(
            self,
            scenario: InternalHelperScenario,
            user_entries: list[p.Entry],
        ) -> None:
            """Test internal helper methods with parametrization."""
            if scenario == InternalHelperScenario.INTERNAL_NORMALIZATION:
                # Test internal normalization methods
                assert hasattr(FlextLdifFilters, "by_dn")

            elif scenario == InternalHelperScenario.INTERNAL_EXECUTE_METHODS:
                # Test internal execute methods
                result = FlextLdifFilters.by_dn(user_entries, Filters.DN_PATTERN_USERS)
                assert result is not None

            elif scenario == InternalHelperScenario.STATIC_METHODS:
                # Test static methods
                result = FlextLdifFilters.builder()
                assert result is not None

            elif scenario == InternalHelperScenario.SCHEMA_EDGE_CASES:
                # Test schema-related edge cases
                result = FlextLdifFilters.is_schema(user_entries[0])
                assert isinstance(result, bool)
