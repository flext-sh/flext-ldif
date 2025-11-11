"""Comprehensive unit tests for FlextLdifFilters.

Tests all ACTUAL filtering methods, patterns, and edge cases with 100% coverage.
Uses REAL implementations without mocks for authentic behavior validation.

This test suite validates:
  ✅ Public classmethod API (by_dn, by_objectclass, by_attributes, by_base_dn, etc)
  ✅ Execute pattern (V1 FlextService style)
  ✅ Classmethod filter() pattern (composable/chainable)
  ✅ Fluent builder pattern
  ✅ All filter criteria (dn, objectclass, attributes, base_dn)
  ✅ All modes (include, exclude)
  ✅ Entry transformation (remove_attributes, remove_objectclasses)
  ✅ Categorization (users, groups, hierarchy, schema, acl, rejected)
  ✅ Schema detection and OID filtering
  ✅ ACL extraction
  ✅ Error handling and edge cases

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import operator

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.services.filters import FlextLdifFilters

# ════════════════════════════════════════════════════════════════════════════
# TEST FIXTURES
# ════════════════════════════════════════════════════════════════════════════


def create_entry(
    dn_str: str,
    attributes: dict[str, list[str]],
) -> FlextLdifModels.Entry:
    """Create test entry with DN and attributes."""
    dn = FlextLdifModels.DistinguishedName(value=dn_str)
    attrs = FlextLdifModels.LdifAttributes.create(attributes).unwrap()
    return FlextLdifModels.Entry(dn=dn, attributes=attrs)


@pytest.fixture
def user_entries() -> list[FlextLdifModels.Entry]:
    """Create user entries for filtering tests."""
    return [
        create_entry(
            "cn=john,ou=users,dc=example,dc=com",
            {"cn": ["john"], "mail": ["john@example.com"], "objectClass": ["person"]},
        ),
        create_entry(
            "cn=jane,ou=users,dc=example,dc=com",
            {"cn": ["jane"], "mail": ["jane@example.com"], "objectClass": ["person"]},
        ),
        create_entry(
            "cn=admin,ou=admins,dc=example,dc=com",
            {"cn": ["admin"], "objectClass": ["person"]},
        ),
    ]


@pytest.fixture
def hierarchy_entries() -> list[FlextLdifModels.Entry]:
    """Create hierarchy/container entries."""
    return [
        create_entry(
            "dc=example,dc=com",
            {"dc": ["example"], "objectClass": ["domain"]},
        ),
        create_entry(
            "ou=users,dc=example,dc=com",
            {"ou": ["users"], "objectClass": ["organizationalUnit"]},
        ),
        create_entry(
            "ou=groups,dc=example,dc=com",
            {"ou": ["groups"], "objectClass": ["organizationalUnit"]},
        ),
    ]


@pytest.fixture
def mixed_entries() -> list[FlextLdifModels.Entry]:
    """Create mixed entry types for categorization."""
    return [
        create_entry(
            "cn=users,ou=groups,dc=example,dc=com",
            {
                "cn": ["users"],
                "objectClass": ["groupOfNames"],
                "member": ["cn=john,ou=users,dc=example,dc=com"],
            },
        ),
        create_entry(
            "cn=acl-policy,dc=example,dc=com",
            {"cn": ["acl-policy"], "acl": ["grant(user1)"]},
        ),
        create_entry(
            "cn=rejected,dc=example,dc=com",
            {"cn": ["rejected"]},
        ),
    ]


@pytest.fixture
def schema_entries() -> list[FlextLdifModels.Entry]:
    """Create schema entries."""
    return [
        create_entry(
            "cn=schema",
            {
                "cn": ["schema"],
                "attributeTypes": [
                    "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )",
                ],
            },
        ),
        create_entry(
            "cn=schema",
            {
                "cn": ["schema"],
                "objectClasses": [
                    "( 2.5.6.6 NAME 'person' SUP top )",
                ],
            },
        ),
    ]


# ════════════════════════════════════════════════════════════════════════════
# TEST PUBLIC CLASSMETHOD API
# ════════════════════════════════════════════════════════════════════════════


class TestPublicClassmethods:
    """Test public classmethod helpers (most direct API)."""

    def test_by_dn_basic(self, user_entries: list[FlextLdifModels.Entry]) -> None:
        """Test by_dn() filters by DN pattern."""
        # With mark_excluded=True, filtered result contains all entries
        # but non-matching are marked as excluded in metadata
        result = FlextLdifFilters.by_dn(
            user_entries,
            "*,ou=users,*",
            mark_excluded=True,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert (
            len(filtered) == 3
        )  # All entries returned (2 matching + 1 marked excluded)

        # Check that matching entries are in the list
        matching = [e for e in filtered if ",ou=users," in e.dn.value]
        assert len(matching) == 2

    def test_by_dn_case_insensitive(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test by_dn() is case-insensitive."""
        result = FlextLdifFilters.by_dn(user_entries, "*,OU=USERS,*")

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2

    def test_by_dn_exclude_mode(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test by_dn() with exclude mode."""
        result = FlextLdifFilters.by_dn(user_entries, "*,ou=users,*", mode="exclude")

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 1
        assert "ou=admins" in filtered[0].dn.value

    def test_by_objectclass_basic(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test by_objectclass() filters by objectClass."""
        result = FlextLdifFilters.by_objectclass(user_entries, "person")

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 3

    def test_by_objectclass_multiple(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test by_objectclass() with multiple objectClasses."""
        result = FlextLdifFilters.by_objectclass(
            user_entries,
            ("person", "organizationalUnit"),
        )

        assert result.is_success
        assert len(result.unwrap()) == 3

    def test_by_objectclass_with_required_attributes(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test by_objectclass() with required attributes."""
        result = FlextLdifFilters.by_objectclass(
            user_entries,
            "person",
            required_attributes=["mail"],
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2  # Only entries with mail
        assert all(e.has_attribute("mail") for e in filtered)

    def test_by_attributes_any(self, user_entries: list[FlextLdifModels.Entry]) -> None:
        """Test by_attributes() with ANY match."""
        result = FlextLdifFilters.by_attributes(user_entries, ["mail"], match_all=False)

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2  # john and jane have mail

    def test_by_attributes_all(self) -> None:
        """Test by_attributes() with ALL match."""
        entries = [
            create_entry(
                "cn=e1,dc=x",
                {"cn": ["e1"], "mail": ["e1@x"], "phone": ["123"]},
            ),
            create_entry("cn=e2,dc=x", {"cn": ["e2"], "mail": ["e2@x"]}),
        ]

        result = FlextLdifFilters.by_attributes(
            entries,
            ["mail", "phone"],
            match_all=True,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 1  # Only e1 has both

    def test_by_base_dn_basic(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test by_base_dn() returns tuple."""
        included, excluded = FlextLdifFilters.by_base_dn(
            hierarchy_entries,
            "dc=example,dc=com",
        )

        assert len(included) == 3
        assert len(excluded) == 0

    def test_by_base_dn_hierarchy(self) -> None:
        """Test by_base_dn() respects hierarchy."""
        entries = [
            create_entry("dc=example,dc=com", {"dc": ["example"]}),
            create_entry("ou=users,dc=example,dc=com", {"ou": ["users"]}),
            create_entry("cn=john,ou=users,dc=example,dc=com", {"cn": ["john"]}),
            create_entry("dc=other,dc=org", {"dc": ["other"]}),
        ]

        included, excluded = FlextLdifFilters.by_base_dn(entries, "dc=example,dc=com")

        assert len(included) == 3
        assert len(excluded) == 1

    def test_is_schema_detection(
        self,
        schema_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test is_schema() detects schema entries."""
        assert FlextLdifFilters.is_schema(schema_entries[0])
        assert FlextLdifFilters.is_schema(schema_entries[1])

    def test_is_schema_non_schema(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test is_schema() returns False for non-schema."""
        assert not FlextLdifFilters.is_schema(user_entries[0])

    def test_extract_acl_entries(
        self,
        mixed_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test extract_acl_entries() extracts ACL entries."""
        result = FlextLdifFilters.extract_acl_entries(mixed_entries)

        assert result.is_success
        acl_entries = result.unwrap()
        assert len(acl_entries) == 1
        assert "acl" in acl_entries[0].attributes.attributes

    def test_remove_attributes(self, user_entries: list[FlextLdifModels.Entry]) -> None:
        """Test remove_attributes() removes attributes."""
        entry = user_entries[0]
        result = FlextLdifFilters.remove_attributes(entry, ["mail"])

        assert result.is_success
        filtered = result.unwrap()
        assert not filtered.has_attribute("mail")
        assert filtered.has_attribute("cn")

    def test_remove_objectclasses(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test remove_objectclasses() removes objectClasses."""
        # Create entry with multiple objectClasses
        entry = create_entry(
            "cn=test,dc=x",
            {"cn": ["test"], "objectClass": ["top", "person"]},
        )

        result = FlextLdifFilters.remove_objectclasses(entry, ["person"])

        assert result.is_success
        filtered = result.unwrap()
        ocs = filtered.get_attribute_values("objectClass")
        assert "person" not in ocs
        assert "top" in ocs

    def test_categorize_users(self) -> None:
        """Test categorize() identifies users."""
        entry = create_entry(
            "cn=john,ou=users,dc=example,dc=com",
            {"cn": ["john"], "mail": ["john@example.com"], "objectClass": ["person"]},
        )

        rules = {
            "user_objectclasses": ["person"],
            "hierarchy_objectclasses": ["organizationalUnit"],
        }

        category, reason = FlextLdifFilters.categorize(entry, rules)

        assert category == "users"
        assert reason is None

    def test_categorize_hierarchy(self) -> None:
        """Test categorize() identifies hierarchy."""
        entry = create_entry(
            "ou=users,dc=example,dc=com",
            {"ou": ["users"], "objectClass": ["organizationalUnit"]},
        )

        rules = {
            "hierarchy_objectclasses": ["organizationalUnit"],
            "user_objectclasses": ["person"],
        }

        category, _reason = FlextLdifFilters.categorize(entry, rules)

        assert category == "hierarchy"

    def test_categorize_schema(
        self,
        schema_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test categorize() identifies schema."""
        category, _reason = FlextLdifFilters.categorize(schema_entries[0], {})

        assert category == "schema"

    def test_categorize_acl(self) -> None:
        """Test categorize() identifies ACL entries."""
        entry = create_entry(
            "cn=policy,dc=example,dc=com",
            {"cn": ["policy"], "acl": ["grant(user1)"]},
        )

        rules = {"acl_attributes": ["acl"]}

        category, _reason = FlextLdifFilters.categorize(entry, rules)

        assert category == "acl"

    def test_categorize_rejected(self) -> None:
        """Test categorize() rejects non-matching."""
        entry = create_entry(
            "cn=unknown,dc=example,dc=com",
            {"cn": ["unknown"]},
        )

        category, reason = FlextLdifFilters.categorize(entry, {})

        assert category == "rejected"
        assert reason is not None


# ════════════════════════════════════════════════════════════════════════════
# TEST EXECUTE PATTERN (V1 Style)
# ════════════════════════════════════════════════════════════════════════════


class TestExecutePattern:
    """Test execute() method for FlextService V1 pattern."""

    def test_execute_empty_entries(self) -> None:
        """Test execute() with empty entries."""
        result = FlextLdifFilters(entries=[], filter_criteria="dn").execute()

        assert result.is_success
        assert len(result.unwrap()) == 0

    def test_execute_dn_filter(self, user_entries: list[FlextLdifModels.Entry]) -> None:
        """Test execute() with DN filter."""
        result = FlextLdifFilters(
            entries=user_entries,
            filter_criteria="dn",
            dn_pattern="*,ou=users,*",
        ).execute()

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2

    def test_execute_objectclass_filter(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test execute() with objectClass filter."""
        result = FlextLdifFilters(
            entries=user_entries,
            filter_criteria="objectclass",
            objectclass="person",
        ).execute()

        assert result.is_success
        assert len(result.unwrap()) == 3

    def test_execute_attributes_filter(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test execute() with attributes filter."""
        result = FlextLdifFilters(
            entries=user_entries,
            filter_criteria="attributes",
            attributes=["mail"],
        ).execute()

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2


# ════════════════════════════════════════════════════════════════════════════
# TEST CLASSMETHOD FILTER PATTERN (Composable/Chainable)
# ════════════════════════════════════════════════════════════════════════════


class TestClassmethodFilter:
    """Test filter() classmethod for composable/chainable operations."""

    def test_filter_dn(self, user_entries: list[FlextLdifModels.Entry]) -> None:
        """Test filter() with DN criteria."""
        result = FlextLdifFilters.filter(
            user_entries,
            criteria="dn",
            pattern="*,ou=users,*",
        )

        assert result.is_success
        assert len(result.unwrap()) == 2

    def test_filter_with_chaining(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filter() with chainable map operations."""
        result = (
            FlextLdifFilters.filter(
                user_entries,
                criteria="dn",
                pattern="*,ou=users,*",
            ).map(operator.itemgetter(slice(1)))  # Take first
        )

        assert result.is_success
        assert len(result.unwrap()) == 1

    def test_filter_objectclass(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filter() with objectClass criteria."""
        result = FlextLdifFilters.filter(
            user_entries,
            criteria="objectclass",
            objectclass="person",
            required_attributes=["mail"],
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2


# ════════════════════════════════════════════════════════════════════════════
# TEST FLUENT BUILDER PATTERN
# ════════════════════════════════════════════════════════════════════════════


class TestFluentBuilder:
    """Test fluent builder pattern for complex filtering."""

    def test_builder_basic(self, user_entries: list[FlextLdifModels.Entry]) -> None:
        """Test builder().with_entries().with_dn_pattern().build()."""
        result = (
            FlextLdifFilters.builder()
            .with_entries(user_entries)
            .with_dn_pattern("*,ou=users,*")
            .build()
        )

        # build() returns EntryResult which acts like a list via __len__ and __iter__
        assert len(result) == 2

    def test_builder_objectclass(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test builder with objectClass."""
        result = (
            FlextLdifFilters.builder()
            .with_entries(user_entries)
            .with_objectclass("person")
            .with_required_attributes(["mail"])
            .build()
        )

        assert len(result) == 2

    def test_builder_attributes(self) -> None:
        """Test builder with attributes."""
        entries = [
            create_entry("cn=e1,dc=x", {"cn": ["e1"], "mail": ["e1@x"]}),
            create_entry("cn=e2,dc=x", {"cn": ["e2"]}),
        ]

        result = (
            FlextLdifFilters.builder()
            .with_entries(entries)
            .with_attributes(["mail"])
            .build()
        )

        assert len(result) == 1

    def test_builder_exclude_matching(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test builder with exclude_matching()."""
        result = (
            FlextLdifFilters.builder()
            .with_entries(user_entries)
            .with_dn_pattern("*,ou=users,*")
            .exclude_matching()
            .build()
        )

        assert len(result) == 1
        assert "ou=admins" in result[0].dn.value

    def test_builder_chaining(self, user_entries: list[FlextLdifModels.Entry]) -> None:
        """Test builder method chaining returns same instance."""
        builder = FlextLdifFilters.builder()
        b2 = builder.with_entries(user_entries)
        b3 = b2.with_dn_pattern("*,ou=users,*")

        assert builder is b2
        assert b2 is b3


# ════════════════════════════════════════════════════════════════════════════
# TEST FILTER MODES
# ════════════════════════════════════════════════════════════════════════════


class TestFilterModes:
    """Test include/exclude modes."""

    def test_mode_include(self, user_entries: list[FlextLdifModels.Entry]) -> None:
        """Test include mode keeps matches."""
        result = FlextLdifFilters.by_dn(user_entries, "*,ou=users,*", mode="include")

        filtered = result.unwrap()
        assert all(",ou=users," in e.dn.value for e in filtered)

    def test_mode_exclude(self, user_entries: list[FlextLdifModels.Entry]) -> None:
        """Test exclude mode removes matches."""
        result = FlextLdifFilters.by_dn(user_entries, "*,ou=users,*", mode="exclude")

        filtered = result.unwrap()
        assert all(",ou=users," not in e.dn.value for e in filtered)


# ════════════════════════════════════════════════════════════════════════════
# TEST ATTRIBUTE MATCHING
# ════════════════════════════════════════════════════════════════════════════


class TestAttributeMatching:
    """Test ANY/ALL attribute matching."""

    def test_match_any_default(self) -> None:
        """Test match_all=False (ANY) is default."""
        entries = [
            create_entry("cn=e1,dc=x", {"mail": ["m1"], "phone": ["p1"]}),
            create_entry("cn=e2,dc=x", {"mail": ["m2"]}),
            create_entry("cn=e3,dc=x", {}),
        ]

        result = FlextLdifFilters.by_attributes(
            entries,
            ["mail", "phone"],
            match_all=False,
        )

        filtered = result.unwrap()
        assert len(filtered) == 2  # e1 and e2

    def test_match_all(self) -> None:
        """Test match_all=True (ALL)."""
        entries = [
            create_entry("cn=e1,dc=x", {"mail": ["m1"], "phone": ["p1"]}),
            create_entry("cn=e2,dc=x", {"mail": ["m2"]}),
        ]

        result = FlextLdifFilters.by_attributes(
            entries,
            ["mail", "phone"],
            match_all=True,
        )

        filtered = result.unwrap()
        assert len(filtered) == 1  # Only e1


# ════════════════════════════════════════════════════════════════════════════
# TEST SCHEMA OPERATIONS
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaOperations:
    """Test schema detection and filtering."""

    def test_is_schema_with_attributetypes(self) -> None:
        """Test is_schema() detects attributeTypes."""
        entry = create_entry(
            "cn=schema",
            {"attributeTypes": ["( 2.5.4.3 NAME 'cn' )"]},
        )

        assert FlextLdifFilters.is_schema(entry)

    def test_is_schema_with_objectclasses(self) -> None:
        """Test is_schema() detects objectClasses."""
        entry = create_entry(
            "cn=schema",
            {"objectClasses": ["( 2.5.6.6 NAME 'person' )"]},
        )

        assert FlextLdifFilters.is_schema(entry)

    def test_is_schema_with_dn(self) -> None:
        """Test is_schema() detects by DN pattern."""
        entry = create_entry("cn=schema", {})
        assert FlextLdifFilters.is_schema(entry)

    def test_filter_schema_by_oids(
        self,
        schema_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filter_schema_by_oids() filters by OID patterns."""
        result = FlextLdifFilters.filter_schema_by_oids(
            schema_entries,
            {"attributes": ["2.5.4.*"], "objectclasses": ["2.5.6.*"]},
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2


# ════════════════════════════════════════════════════════════════════════════
# TEST TRANSFORMATION
# ════════════════════════════════════════════════════════════════════════════


class TestTransformation:
    """Test attribute and objectClass removal."""

    def test_remove_attributes_case_insensitive(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test remove_attributes() is case-insensitive."""
        entry = user_entries[0]
        result = FlextLdifFilters.remove_attributes(entry, ["MAIL"])

        assert result.is_success
        filtered = result.unwrap()
        assert not filtered.has_attribute("mail")

    def test_remove_objectclasses_fails_if_all_removed(self) -> None:
        """Test remove_objectclasses() fails if all would be removed."""
        entry = create_entry(
            "cn=test,dc=x",
            {"cn": ["test"], "objectClass": ["person"]},
        )

        result = FlextLdifFilters.remove_objectclasses(entry, ["person"])

        assert not result.is_success
        assert "All objectClasses would be removed" in result.error


# ════════════════════════════════════════════════════════════════════════════
# TEST EXCLUSION MARKING
# ════════════════════════════════════════════════════════════════════════════


class TestExclusionMarking:
    """Test exclusion metadata marking."""

    def test_mark_excluded_basic(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test excluded entries are marked."""
        result = FlextLdifFilters.by_dn(
            user_entries,
            "*,ou=users,*",
            mark_excluded=True,
        )

        filtered = result.unwrap()
        # Should have 3 entries: 2 included + 1 excluded marked
        assert len(filtered) == 3

    def test_mark_excluded_false(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test mark_excluded=False removes excluded."""
        result = FlextLdifFilters.by_dn(
            user_entries,
            "*,ou=users,*",
            mark_excluded=False,
        )

        filtered = result.unwrap()
        # Only included entries (2)
        assert len(filtered) == 2


# ════════════════════════════════════════════════════════════════════════════
# TEST EDGE CASES
# ════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Test edge cases and special situations."""

    def test_empty_entries(self) -> None:
        """Test filtering empty entry list."""
        result = FlextLdifFilters.by_dn([], "*,ou=users,*")

        assert result.is_success
        assert result.unwrap() == []

    def test_single_entry(self) -> None:
        """Test filtering single entry."""
        entry = create_entry("cn=test,ou=users,dc=x", {"cn": ["test"]})

        result = FlextLdifFilters.by_dn([entry], "*,ou=users,*")

        assert result.is_success
        assert len(result.unwrap()) == 1

    def test_unicode_dns(self) -> None:
        """Test filtering with Unicode in DNs."""
        entries = [
            create_entry("cn=日本語,dc=example,dc=com", {"cn": ["日本語"]}),
            create_entry("cn=English,dc=example,dc=com", {"cn": ["English"]}),
        ]

        result = FlextLdifFilters.by_dn(entries, "*,dc=example,dc=com")

        assert result.is_success
        assert len(result.unwrap()) == 2

    def test_large_entry_list(self) -> None:
        """Test filtering large number of entries."""
        entries = [
            create_entry(f"cn=user{i:04d},dc=example,dc=com", {"cn": [f"user{i:04d}"]})
            for i in range(100)
        ]

        result = FlextLdifFilters.by_dn(entries, "*,dc=example,dc=com")

        assert result.is_success
        assert len(result.unwrap()) == 100


# ════════════════════════════════════════════════════════════════════════════
# TEST ERROR CASES
# ════════════════════════════════════════════════════════════════════════════


class TestErrorCases:
    """Test error handling and validation."""

    def test_invalid_filter_criteria_validation(self) -> None:
        """Test invalid filter_criteria is rejected."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="Invalid filter_criteria"):
            FlextLdifFilters(
                filter_criteria="invalid",
            )

    def test_invalid_mode_validation(self) -> None:
        """Test invalid mode is rejected."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="Invalid mode"):
            FlextLdifFilters(
                mode="invalid",
            )


# ════════════════════════════════════════════════════════════════════════════
# TEST INTEGRATION
# ════════════════════════════════════════════════════════════════════════════


class TestIntegration:
    """Integration tests for real-world scenarios."""

    def test_multi_stage_filtering(
        self,
        user_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test multi-stage filtering pipeline."""
        # Stage 1: Filter by DN
        result1 = FlextLdifFilters.filter(
            user_entries,
            criteria="dn",
            pattern="*,ou=users,*",
        )
        assert result1.is_success

        # Stage 2: Filter by objectClass
        result2 = FlextLdifFilters.filter(
            result1.unwrap(),
            criteria="objectclass",
            objectclass="person",
        )
        assert result2.is_success
        assert len(result2.unwrap()) == 2

    def test_categorization_pipeline(
        self,
        mixed_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test categorization of mixed entries."""
        rules = {
            "hierarchy_objectclasses": ["organizationalUnit"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": ["acl"],
        }

        categories = {}
        for entry in mixed_entries:
            category, _ = FlextLdifFilters.categorize(entry, rules)
            categories[entry.dn.value] = category

        assert categories["cn=users,ou=groups,dc=example,dc=com"] == "groups"
        assert categories["cn=acl-policy,dc=example,dc=com"] == "acl"
        assert categories["cn=rejected,dc=example,dc=com"] == "rejected"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
