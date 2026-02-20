"""Tests for FlextLdif Filters using real LDIF data.

This module tests the Filter factory class using actual LDIF fixtures,
validating filtering and deduplication on real-world LDAP data.

The Filter class from _utilities/filters.py provides composable filters:
    - Filter.by_dn(pattern) - Regex pattern matching on DN
    - Filter.by_dn_under(base_dn) - Entries under a base DN
    - Filter.by_objectclass(*classes) - Match by objectClass
    - Filter.by_attrs(*attrs) - Match by attribute presence
    - Filter.is_schema() - Match schema entries

Filters support composition via operators:
    - filter1 & filter2 - AND combination
    - filter1 | filter2 - OR combination
    - ~filter - NOT (negation)
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from pathlib import Path
from typing import Final

import pytest
from flext_ldif import FlextLdif
from flext_ldif._utilities.filters import Filter

from tests import Filters, c, p


class FilterScenarios(StrEnum):
    """Test scenarios for filter service operations."""

    DN_PATTERN_FILTERING = "dn_pattern_filtering"
    OBJECTCLASS_FILTERING = "objectclass_filtering"
    ATTRIBUTE_FILTERING = "attribute_filtering"
    BASE_DN_FILTERING = "base_dn_filtering"
    SCHEMA_DETECTION = "schema_detection"
    COMPOSITE_FILTERING = "composite_filtering"
    MULTI_STAGE_FILTERING = "multi_stage_filtering"


@dataclasses.dataclass(frozen=True)
class DnPatternTestCase:
    """DN pattern filtering test case."""

    name: str
    pattern: str
    expected_contains: str


@dataclasses.dataclass(frozen=True)
class ObjectClassTestCase:
    """ObjectClass filtering test case."""

    name: str
    objectclass: str
    expected_attr: str


@dataclasses.dataclass(frozen=True)
class AttributeFilterTestCase:
    """Attribute filtering test case."""

    name: str
    attributes: list[str]
    expected_attr: str | None = None
    expected_attrs: list[str] | None = None
    match_all: bool = False


@dataclasses.dataclass(frozen=True)
class BaseDnTestCase:
    """Base DN hierarchy test case."""

    name: str
    base_dn: str
    expected_contains: str = ""


# Test case definitions using constants
DN_PATTERN_TESTS: Final[list[DnPatternTestCase]] = [
    DnPatternTestCase("people", r".*ou=users.*", "ou=users"),
    DnPatternTestCase("groups", r".*ou=groups.*", "ou=groups"),
    DnPatternTestCase("organizational_unit", r".*ou=.*", "ou="),
]

OBJECTCLASS_TESTS: Final[list[ObjectClassTestCase]] = [
    ObjectClassTestCase("inetorgperson", c.Names.INETORGPERSON, Filters.ATTR_MAIL),
    ObjectClassTestCase("groupofnames", Filters.OC_GROUP_OF_NAMES, "member"),
    ObjectClassTestCase("organizationalunit", Filters.OC_ORGANIZATIONAL_UNIT, "ou"),
    ObjectClassTestCase("person", c.Names.PERSON, Filters.ATTR_SN),
]

ATTRIBUTE_FILTER_TESTS: Final[list[AttributeFilterTestCase]] = [
    AttributeFilterTestCase(
        "mail_only",
        [Filters.ATTR_MAIL],
        expected_attr=Filters.ATTR_MAIL,
    ),
    AttributeFilterTestCase(
        "multiple_any",
        [Filters.ATTR_MAIL, Filters.ATTR_SN],
        expected_attr=Filters.ATTR_MAIL,
        match_all=False,
    ),
    AttributeFilterTestCase(
        "multiple_all",
        [Filters.ATTR_MAIL, Filters.ATTR_SN],
        expected_attrs=[Filters.ATTR_MAIL, Filters.ATTR_SN],
        match_all=True,
    ),
]

BASE_DN_TESTS: Final[list[BaseDnTestCase]] = [
    BaseDnTestCase("example_com", "dc=example,dc=com"),
    BaseDnTestCase("people_ou", Filters.DN_OU_USERS, "ou=users"),
    BaseDnTestCase("groups_ou", Filters.DN_OU_GROUPS, "ou=groups"),
]


def load_real_ldif_entries(fixture_path: str) -> list[p.Entry]:
    """Load REAL LDIF entries from fixture file (no mocks)."""
    fixture_file = Path(__file__).parent.parent.parent / "fixtures" / fixture_path
    if not fixture_file.exists():
        pytest.skip(f"Fixture file not found: {fixture_path}")

    ldif = FlextLdif()
    result = ldif.parse(fixture_file)

    if not result.is_success:
        pytest.skip(f"Failed to parse fixture: {result.error}")

    return result.value


@pytest.fixture(scope="module")
def oid_entries() -> list[p.Entry]:
    """Load real OID LDIF entries (module-scoped to avoid repeated parsing)."""
    return load_real_ldif_entries("oid/oid_entries_fixtures.ldif")


@pytest.fixture(scope="module")
def oid_schema_entries() -> list[p.Entry]:
    """Load real OID schema entries (module-scoped to avoid repeated parsing)."""
    return load_real_ldif_entries("oid/oid_schema_fixtures.ldif")


@pytest.fixture(scope="module")
def oid_acl_entries() -> list[p.Entry]:
    """Load real OID ACL entries (module-scoped to avoid repeated parsing)."""
    return load_real_ldif_entries("oid/oid_acl_fixtures.ldif")


def _get_dn_str(entry: p.Entry) -> str:
    """Get DN string from entry."""
    if entry.dn is None:
        return ""
    return entry.dn.value if hasattr(entry.dn, "value") else str(entry.dn)


def _entry_has_attribute(entry: p.Entry, attr_name: str) -> bool:
    """Check if entry has a specific attribute."""
    if entry.attributes is None:
        return False
    attrs = (
        entry.attributes.attributes if hasattr(entry.attributes, "attributes") else {}
    )
    return any(k.lower() == attr_name.lower() for k in attrs)


def _get_objectclasses(entry: p.Entry) -> list[str]:
    """Get objectClass values from entry."""
    if entry.attributes is None:
        return []
    attrs = (
        entry.attributes.attributes if hasattr(entry.attributes, "attributes") else {}
    )
    for attr_name, values in attrs.items():
        if attr_name.lower() == "objectclass":
            return list(values)
    return []


class TestFlextLdifFilterService:
    """Comprehensive filter service tests using REAL LDIF fixtures.

    Uses the Filter factory class from _utilities/filters.py with composable
    filter objects. Tests validate DN patterns, objectClass, attributes,
    and composite filtering.
    """

    @pytest.mark.parametrize("test_case", DN_PATTERN_TESTS)
    def test_dn_pattern_filtering(
        self,
        test_case: DnPatternTestCase,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test DN pattern filtering using Filter.by_dn()."""
        dn_filter = Filter.by_dn(test_case.pattern)
        filtered = dn_filter.filter(oid_entries)

        assert len(filtered) > 0, f"No entries matched pattern {test_case.pattern}"

        # Verify all filtered entries contain expected string
        for entry in filtered:
            dn_str = _get_dn_str(entry)
            assert test_case.expected_contains.lower() in dn_str.lower(), (
                f"Entry DN '{dn_str}' does not contain '{test_case.expected_contains}'"
            )

    def test_dn_filter_excludes_non_matching(
        self,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test that non-matching entries are excluded using Filter.by_dn()."""
        # Filter for users only
        users_filter = Filter.by_dn(r".*ou=users.*")
        filtered = users_filter.filter(oid_entries)

        # The base domain entry should not be in filtered results
        base_entries = [
            e for e in filtered if _get_dn_str(e).lower() == "dc=example,dc=com"
        ]
        assert len(base_entries) == 0, "Base domain entry should be excluded"

    def test_dn_filter_negation(
        self,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test negation filter with ~ operator."""
        original_count = len(oid_entries)
        # Exclude users with negation
        exclude_users_filter = ~Filter.by_dn(r".*ou=users.*")
        filtered = exclude_users_filter.filter(oid_entries)

        assert len(filtered) < original_count, (
            "Should have fewer entries after excluding users"
        )

        # Verify no users in result
        for entry in filtered:
            dn_str = _get_dn_str(entry)
            assert "ou=users" not in dn_str.lower(), (
                f"Users entry '{dn_str}' should be excluded"
            )

    @pytest.mark.parametrize("test_case", OBJECTCLASS_TESTS)
    def test_objectclass_filtering(
        self,
        test_case: ObjectClassTestCase,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test objectClass filtering using Filter.by_objectclass()."""
        oc_filter = Filter.by_objectclass(test_case.objectclass)
        filtered = oc_filter.filter(oid_entries)

        assert len(filtered) > 0, (
            f"No entries matched objectClass {test_case.objectclass}"
        )

        # Verify all filtered entries have the objectClass
        for entry in filtered:
            ocs = _get_objectclasses(entry)
            assert any(oc.lower() == test_case.objectclass.lower() for oc in ocs), (
                f"Entry missing objectClass {test_case.objectclass}"
            )

    @pytest.mark.parametrize("test_case", ATTRIBUTE_FILTER_TESTS)
    def test_attribute_filtering(
        self,
        test_case: AttributeFilterTestCase,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test attribute filtering using Filter.by_attrs()."""
        mode = "all" if test_case.match_all else "any"
        attrs_filter = Filter.by_attrs(*test_case.attributes, mode=mode)
        filtered = attrs_filter.filter(oid_entries)

        assert len(filtered) > 0, (
            f"No entries matched attributes {test_case.attributes}"
        )

        # Verify filtered entries have expected attributes
        for entry in filtered:
            if test_case.match_all and test_case.expected_attrs:
                # All attributes must be present
                for attr in test_case.expected_attrs:
                    assert _entry_has_attribute(entry, attr), (
                        f"Entry missing required attribute {attr}"
                    )
            elif test_case.expected_attr:
                # At least one attribute present (any mode)
                has_any = any(
                    _entry_has_attribute(entry, attr) for attr in test_case.attributes
                )
                assert has_any, (
                    f"Entry missing any of attributes {test_case.attributes}"
                )

    @pytest.mark.parametrize("test_case", BASE_DN_TESTS)
    def test_base_dn_filtering(
        self,
        test_case: BaseDnTestCase,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test base DN filtering using Filter.by_dn_under()."""
        base_filter = Filter.by_dn_under(test_case.base_dn)
        filtered = base_filter.filter(oid_entries)

        assert len(filtered) > 0, f"No entries under base DN {test_case.base_dn}"

        # Verify all filtered entries are under the base DN
        for entry in filtered:
            dn_str = _get_dn_str(entry)
            assert dn_str.lower().endswith(test_case.base_dn.lower()) or (
                f",{test_case.base_dn.lower()}" in dn_str.lower()
            ), f"Entry DN '{dn_str}' is not under base DN '{test_case.base_dn}'"

    def test_schema_detection(
        self,
        oid_schema_entries: list[p.Entry],
    ) -> None:
        """Test schema entry detection using Filter.is_schema()."""
        schema_filter = Filter.is_schema()
        schema_entries = schema_filter.filter(oid_schema_entries)

        assert len(schema_entries) > 0, "Should detect schema entries"

        # Verify schema entries have schema attributes
        for entry in schema_entries:
            has_schema_attr = (
                _entry_has_attribute(entry, "attributeTypes")
                or _entry_has_attribute(entry, "objectClasses")
                or _entry_has_attribute(entry, "ldapSyntaxes")
            )
            assert has_schema_attr, "Schema entry should have schema attributes"

    def test_composite_filter_and(
        self,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test composite AND filter with & operator."""
        # Users who are inetOrgPerson
        composite = Filter.by_dn(r".*ou=users.*") & Filter.by_objectclass(
            "inetOrgPerson"
        )
        filtered = composite.filter(oid_entries)

        # Verify both conditions met
        for entry in filtered:
            dn_str = _get_dn_str(entry)
            assert "ou=users" in dn_str.lower(), "Entry should be in users OU"

            ocs = _get_objectclasses(entry)
            assert any(oc.lower() == "inetorgperson" for oc in ocs), (
                "Entry should be inetOrgPerson"
            )

    def test_composite_filter_or(
        self,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test composite OR filter with | operator."""
        # Users OR groups
        composite = Filter.by_dn(r".*ou=users.*") | Filter.by_dn(r".*ou=groups.*")
        filtered = composite.filter(oid_entries)

        # Verify at least one condition met
        for entry in filtered:
            dn_str = _get_dn_str(entry)
            assert "ou=users" in dn_str.lower() or "ou=groups" in dn_str.lower(), (
                f"Entry '{dn_str}' should be in users OR groups OU"
            )

    def test_multi_stage_filtering(
        self,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test complex multi-stage filtering pipeline."""
        # Stage 1: Filter to users OU
        stage1_filter = Filter.by_dn(r".*ou=users.*")
        stage1_entries = stage1_filter.filter(oid_entries)

        # Stage 2: Filter to inetOrgPerson
        stage2_filter = Filter.by_objectclass("inetOrgPerson")
        stage2_entries = stage2_filter.filter(stage1_entries)

        # Stage 3: Filter to those with mail attribute
        stage3_filter = Filter.by_attrs("mail")
        final_entries = stage3_filter.filter(stage2_entries)

        # Pipeline should reduce entry count at each stage
        assert len(final_entries) <= len(stage1_entries), (
            "Pipeline should reduce or maintain entry count"
        )

        # Verify final entries meet all criteria
        for entry in final_entries:
            dn_str = _get_dn_str(entry)
            assert "ou=users" in dn_str.lower(), "Entry should be in users OU"

            ocs = _get_objectclasses(entry)
            assert any(oc.lower() == "inetorgperson" for oc in ocs), (
                "Entry should be inetOrgPerson"
            )

            assert _entry_has_attribute(entry, "mail"), (
                "Entry should have mail attribute"
            )

    def test_composite_multi_condition(
        self,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test multi-condition composite filter."""
        # Users who are inetOrgPerson with mail attribute
        composite = (
            Filter.by_dn(r".*ou=users.*")
            & Filter.by_objectclass("inetOrgPerson")
            & Filter.by_attrs("mail")
        )
        filtered = composite.filter(oid_entries)

        # All three conditions must be met
        for entry in filtered:
            dn_str = _get_dn_str(entry)
            assert "ou=users" in dn_str.lower(), "Entry should be in users OU"

            ocs = _get_objectclasses(entry)
            assert any(oc.lower() == "inetorgperson" for oc in ocs), (
                "Entry should be inetOrgPerson"
            )

            assert _entry_has_attribute(entry, "mail"), (
                "Entry should have mail attribute"
            )

    def test_error_handling_empty_input(self) -> None:
        """Test error handling for edge cases with empty input."""
        dn_filter = Filter.by_dn(r".*pattern.*")
        filtered = dn_filter.filter([])

        assert len(filtered) == 0, "Empty input should return empty result"

    def test_custom_filter_predicate(
        self,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test custom filter with predicate function."""

        def has_long_dn(entry: p.Entry) -> bool:
            """Custom predicate: DN length > 30 chars."""
            dn_str = _get_dn_str(entry)
            return len(dn_str) > 30

        custom_filter = Filter.custom(has_long_dn)
        filtered = custom_filter.filter(oid_entries)

        # Verify all filtered entries have long DNs
        for entry in filtered:
            dn_str = _get_dn_str(entry)
            assert len(dn_str) > 30, f"DN '{dn_str}' should be longer than 30 chars"


if __name__ == "__main__":
    _ = pytest.main([__file__, "-v"])
