from __future__ import annotations

from typing import Final

import pytest
from flext_core._models.collections import FlextModelsCollections

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.categorization import FlextLdifCategorization
from flext_ldif.services.server import FlextLdifServer
from tests import Filters, TestCategorization, c, m, s

# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)


class TestsFlextLdifCategorization(s):
    """Comprehensive tests for FlextLdifCategorization service.

    Single class with nested test groups following project patterns.
    Uses factories, parametrization, and helpers for DRY code.
    """

    class Constants:
        """Test constants organized in nested class."""

        # Server types
        SERVER_RFC: Final[str] = Filters.SERVER_RFC
        SERVER_OID: Final[str] = Filters.SERVER_OID
        SERVER_OUD: Final[str] = Filters.SERVER_OUD

        # Categories
        CATEGORY_SCHEMA: Final[str] = FlextLdifConstants.Categories.SCHEMA
        CATEGORY_HIERARCHY: Final[str] = FlextLdifConstants.Categories.HIERARCHY
        CATEGORY_USERS: Final[str] = FlextLdifConstants.Categories.USERS
        CATEGORY_GROUPS: Final[str] = FlextLdifConstants.Categories.GROUPS
        CATEGORY_ACL: Final[str] = FlextLdifConstants.Categories.ACL
        CATEGORY_REJECTED: Final[str] = FlextLdifConstants.Categories.REJECTED

        # Test DNs
        DN_BASE: Final[str] = c.DNs.EXAMPLE
        DN_USER: Final[str] = Filters.DN_USER_JOHN
        DN_GROUP: Final[str] = c.DNs.TEST_GROUP
        DN_OU: Final[str] = Filters.DN_OU_USERS
        DN_SCHEMA: Final[str] = c.DNs.SCHEMA

        # ObjectClasses
        OC_PERSON: Final[str] = c.Names.PERSON
        OC_INET_ORG_PERSON: Final[str] = c.Names.INET_ORG_PERSON
        OC_GROUP_OF_NAMES: Final[str] = Filters.OC_GROUP_OF_NAMES
        OC_ORGANIZATIONAL_UNIT: Final[str] = Filters.OC_ORGANIZATIONAL_UNIT

    class Factories:
        """Entry factories for categorization tests."""

        @staticmethod
        def create_user_entry(
            dn: str = Filters.DN_USER_JOHN,
            **overrides: str | list[str],
        ) -> m.Entry:
            """Create user entry for testing."""
            attrs: dict[str, str | list[str]] = {
                c.Names.OBJECTCLASS: [
                    c.Names.INET_ORG_PERSON,
                    c.Names.ORGANIZATIONAL_PERSON,
                    c.Names.PERSON,
                    c.Names.TOP,
                ],
                c.Names.CN: [c.Values.USER],
                c.Names.SN: [c.Values.USER],
            }
            attrs.update(overrides)
            return self.create_entry(dn, attrs)

        @staticmethod
        def create_group_entry(
            dn: str = c.DNs.TEST_GROUP,
            **overrides: str | list[str],
        ) -> m.Entry:
            """Create group entry for testing."""
            attrs: dict[str, str | list[str]] = {
                c.Names.OBJECTCLASS: [Filters.OC_GROUP_OF_NAMES, c.Names.TOP],
                c.Names.CN: [c.Values.TEST],
                "member": [Filters.DN_USER_JOHN],
            }
            attrs.update(overrides)
            return self.create_entry(dn, attrs)

        @staticmethod
        def create_hierarchy_entry(
            dn: str = Filters.DN_OU_USERS,
            **overrides: str | list[str],
        ) -> m.Entry:
            """Create hierarchy entry for testing."""
            attrs: dict[str, str | list[str]] = {
                c.Names.OBJECTCLASS: [
                    Filters.OC_ORGANIZATIONAL_UNIT,
                    c.Names.TOP,
                ],
                "ou": [c.Values.USER],
            }
            attrs.update(overrides)
            return self.create_entry(dn, attrs)

        @staticmethod
        def create_schema_entry(
            dn: str = c.DNs.SCHEMA,
            **overrides: str | list[str],
        ) -> m.Entry:
            """Create schema entry for testing."""
            attrs: dict[str, str | list[str]] = {
                c.Names.OBJECTCLASS: [c.Names.TOP, "subschema"],
                "attributeTypes": [
                    f"( {OIDs.CN} NAME '{c.Names.CN}' SYNTAX {OIDs.DIRECTORY_STRING} )",
                ],
            }
            attrs.update(overrides)
            return self.create_entry(dn, attrs)

        @staticmethod
        def create_acl_entry(
            dn: str = Filters.DN_ACL_POLICY,
            **overrides: str | list[str],
        ) -> m.Entry:
            """Create ACL entry for testing."""
            attrs: dict[str, str | list[str]] = {
                c.Names.OBJECTCLASS: [c.Names.TOP],
                c.Names.CN: [c.Values.TEST],
                "aci": ['(targetattr="*")(version 3.0;acl "test";allow (all) )'],
            }
            attrs.update(overrides)
            return self.create_entry(dn, attrs)

    class TestDNValidation:
        """Test DN validation and normalization."""

        def test_validate_dns_valid_entries(self) -> None:
            """Test validate_dns() with valid entries."""
            entries = [
                TestCategorization.Factories.create_user_entry(),
                TestCategorization.Factories.create_group_entry(),
            ]
            service = FlextLdifCategorization()
            result = service.validate_dns(entries)
            validated = self.assert_success(result)
            assert len(validated) == 2

        def test_validate_dns_invalid_dn_rejected(self) -> None:
            """Test validate_dns() rejects invalid c.DNs."""
            invalid_entry = self.create_entry(
                "invalid dn format",
                {c.Names.CN: [c.Values.TEST]},
            )
            service = FlextLdifCategorization()
            result = service.validate_dns([invalid_entry])
            validated = self.assert_success(result)
            assert len(validated) == 0
            assert len(service.rejection_tracker["invalid_dn_rfc4514"]) == 1

        def test_validate_dns_normalizes_dn(self) -> None:
            """Test validate_dns() normalizes DN case."""
            entry = self.create_entry(
                "CN=Test,DC=Example,DC=Com",
                {c.Names.CN: [c.Values.TEST]},
            )
            service = FlextLdifCategorization()
            result = service.validate_dns([entry])
            validated = self.assert_success(result)
            assert len(validated) == 1
            # DN.norm() normalizes attribute names to lowercase but preserves value case
            assert validated[0].dn.value == "cn=Test,dc=Example,dc=Com"

        def test_validate_dns_tracks_rejection_metadata(self) -> None:
            """Test validate_dns() tracks rejection in metadata."""
            invalid_entry = self.create_entry(
                "invalid dn",
                {c.Names.CN: [c.Values.TEST]},
            )
            # Add processing_stats to entry
            stats = m.EntryStatistics()
            metadata = m.QuirkMetadata(
                quirk_type=Filters.SERVER_RFC,
                processing_stats=stats,
            )
            entry_with_stats = invalid_entry.model_copy(update={"metadata": metadata})

            service = FlextLdifCategorization()
            _ = service.validate_dns([entry_with_stats])
            rejected = service.rejection_tracker["invalid_dn_rfc4514"][0]
            assert rejected.metadata is not None
            assert rejected.metadata.processing_stats is not None
            assert rejected.metadata.processing_stats.was_rejected
            assert (
                rejected.metadata.processing_stats.rejection_category
                == FlextLdifConstants.RejectionCategory.INVALID_DN
            )

    class TestSchemaDetection:
        """Test schema entry detection."""

        def test_is_schema_entry_with_attributetypes(self) -> None:
            """Test is_schema_entry() detects attributeTypes."""
            entry = TestCategorization.Factories.create_schema_entry()
            service = FlextLdifCategorization()
            assert service.is_schema_entry(entry)

        def test_is_schema_entry_with_objectclasses(self) -> None:
            """Test is_schema_entry() detects objectClasses."""
            entry = self.create_entry(
                TestCategorization.Constants.DN_SCHEMA,
                {
                    c.Names.OBJECTCLASS: [c.Names.TOP],
                    "objectClasses": [f"( {OIDs.PERSON} NAME '{c.Names.PERSON}' )"],
                },
            )
            service = FlextLdifCategorization()
            assert service.is_schema_entry(entry)

        def test_is_schema_entry_with_ldapsyntaxes(self) -> None:
            """Test is_schema_entry() detects ldapSyntaxes."""
            entry = self.create_entry(
                TestCategorization.Constants.DN_SCHEMA,
                {
                    c.Names.OBJECTCLASS: [c.Names.TOP],
                    "ldapSyntaxes": [f"( {OIDs.DIRECTORY_STRING} )"],
                },
            )
            service = FlextLdifCategorization()
            assert service.is_schema_entry(entry)

        def test_is_schema_entry_with_matchingrules(self) -> None:
            """Test is_schema_entry() detects matchingRules."""
            entry = self.create_entry(
                TestCategorization.Constants.DN_SCHEMA,
                {
                    c.Names.OBJECTCLASS: [c.Names.TOP],
                    "matchingRules": ["( 2.5.13.2 NAME 'caseIgnoreMatch' )"],
                },
            )
            service = FlextLdifCategorization()
            assert service.is_schema_entry(entry)

        def test_is_schema_entry_non_schema(self) -> None:
            """Test is_schema_entry() returns False for non-schema entries."""
            entry = TestCategorization.Factories.create_user_entry()
            service = FlextLdifCategorization()
            assert not service.is_schema_entry(entry)

    class TestEntryCategorization:
        """Test single entry categorization."""

        @pytest.mark.parametrize(
            ("entry_factory", "server_type", "expected_category"),
            [
                (
                    "create_user_entry",
                    Filters.SERVER_RFC,
                    FlextLdifConstants.Categories.USERS,
                ),
                (
                    "create_group_entry",
                    Filters.SERVER_RFC,
                    FlextLdifConstants.Categories.GROUPS,
                ),
                (
                    "create_hierarchy_entry",
                    Filters.SERVER_RFC,
                    FlextLdifConstants.Categories.HIERARCHY,
                ),
                (
                    "create_schema_entry",
                    Filters.SERVER_RFC,
                    FlextLdifConstants.Categories.SCHEMA,
                ),
                (
                    "create_acl_entry",
                    Filters.SERVER_OUD,
                    FlextLdifConstants.Categories.ACL,
                ),
            ],
        )
        def test_categorize_entry_by_type(
            self,
            entry_factory: str,
            server_type: str,
            expected_category: str,
        ) -> None:
            """Test categorize_entry() categorizes by entry type."""
            factory_method = getattr(TestCategorization.Factories, entry_factory)
            entry = factory_method()
            service = FlextLdifCategorization(server_type=server_type)
            category, reason = service.categorize_entry(entry, None, server_type)
            assert category == expected_category
            assert reason is None

        def test_categorize_entry_rejected_no_match(self) -> None:
            """Test categorize_entry() rejects entries with no match."""
            # Create entry with no objectClass that matches any category
            entry = self.create_entry(
                "cn=unknown,dc=example,dc=com",
                {c.Names.CN: [c.Values.TEST]},
            )
            # Remove all objectClasses to ensure rejection
            attrs = entry.attributes.model_copy()
            attrs.attributes.pop(c.Names.OBJECTCLASS, None)
            entry = entry.model_copy(update={"attributes": attrs})
            service = FlextLdifCategorization()
            category, reason = service.categorize_entry(entry)
            assert category == TestCategorization.Constants.CATEGORY_REJECTED
            assert reason is not None

        def test_categorize_entry_with_server_type_oid(self) -> None:
            """Test categorize_entry() with OID server type."""
            entry = self.create_entry(
                "cn=test,dc=oracle",
                {
                    c.Names.OBJECTCLASS: ["orcluser"],
                    c.Names.CN: [c.Values.TEST],
                },
            )
            service = FlextLdifCategorization(
                server_type=TestCategorization.Constants.SERVER_OID,
            )
            category, _reason = service.categorize_entry(entry)
            assert category in {
                TestCategorization.Constants.CATEGORY_USERS,
                TestCategorization.Constants.CATEGORY_REJECTED,
            }

        def test_categorize_entry_with_invalid_server_type(self) -> None:
            """Test categorize_entry() handles invalid server type."""
            entry = TestCategorization.Factories.create_user_entry()
            service = FlextLdifCategorization(server_type="invalid")
            category, reason = service.categorize_entry(entry)
            assert category == TestCategorization.Constants.CATEGORY_REJECTED
            assert reason is not None
            assert (
                "Unknown server type" in reason
                or "missing required attributes" in reason
            )

        def test_categorize_entry_hierarchy_priority(self) -> None:
            """Test categorize_entry() respects hierarchy priority."""
            # Entry with both hierarchy and group objectClasses
            entry = self.create_entry(
                "cn=container,dc=oracle",
                {
                    c.Names.OBJECTCLASS: [
                        "orclContainer",
                        "orclprivilegegroup",
                    ],
                    c.Names.CN: [c.Values.TEST],
                },
            )
            service = FlextLdifCategorization(
                server_type=TestCategorization.Constants.SERVER_OID,
            )
            category, _reason = service.categorize_entry(entry)
            # Hierarchy should have priority
            assert category == TestCategorization.Constants.CATEGORY_HIERARCHY

    class TestEntriesCategorization:
        """Test multiple entries categorization."""

        def test_categorize_entries_mixed_types(self) -> None:
            """Test categorize_entries() with mixed entry types."""
            entries = [
                TestCategorization.Factories.create_user_entry(),
                TestCategorization.Factories.create_group_entry(),
                TestCategorization.Factories.create_hierarchy_entry(),
                TestCategorization.Factories.create_schema_entry(),
            ]
            service = FlextLdifCategorization()
            result = service.categorize_entries(entries)
            categories = self.assert_success(result)
            assert len(categories[TestCategorization.Constants.CATEGORY_USERS]) == 1
            assert len(categories[TestCategorization.Constants.CATEGORY_GROUPS]) == 1
            assert len(categories[TestCategorization.Constants.CATEGORY_HIERARCHY]) == 1
            assert len(categories[TestCategorization.Constants.CATEGORY_SCHEMA]) == 1

        def test_categorize_entries_tracks_metadata(self) -> None:
            """Test categorize_entries() tracks category in metadata."""
            entry = TestCategorization.Factories.create_user_entry()
            # Add processing_stats
            stats = m.EntryStatistics()
            metadata = m.QuirkMetadata(
                quirk_type=Filters.SERVER_RFC,
                processing_stats=stats,
            )
            entry_with_stats = entry.model_copy(update={"metadata": metadata})

            service = FlextLdifCategorization()
            result = service.categorize_entries([entry_with_stats])
            categories = self.assert_success(result)
            categorized_entry = categories[TestCategorization.Constants.CATEGORY_USERS][
                0
            ]
            assert categorized_entry.metadata is not None
            assert categorized_entry.metadata.processing_stats is not None
            assert (
                categorized_entry.metadata.processing_stats.category_assigned
                == TestCategorization.Constants.CATEGORY_USERS
            )

        def test_categorize_entries_tracks_rejected_metadata(self) -> None:
            """Test categorize_entries() tracks rejected entries in metadata."""
            entry = self.create_entry(
                "cn=unknown,dc=example,dc=com",
                {c.Names.CN: [c.Values.TEST]},
            )
            # Remove all objectClasses to ensure rejection
            attrs = entry.attributes.model_copy()
            attrs.attributes.pop(c.Names.OBJECTCLASS, None)
            entry = entry.model_copy(update={"attributes": attrs})
            # Add processing_stats
            stats = m.EntryStatistics()
            metadata = m.QuirkMetadata(
                quirk_type=Filters.SERVER_RFC,
                processing_stats=stats,
            )
            entry_with_stats = entry.model_copy(update={"metadata": metadata})

            service = FlextLdifCategorization()
            result = service.categorize_entries([entry_with_stats])
            categories = self.assert_success(result)
            assert len(categories[TestCategorization.Constants.CATEGORY_REJECTED]) > 0
            rejected = categories[TestCategorization.Constants.CATEGORY_REJECTED][0]
            assert rejected.metadata is not None
            assert rejected.metadata.processing_stats is not None
            assert rejected.metadata.processing_stats.was_rejected
            assert (
                rejected.metadata.processing_stats.rejection_category
                == FlextLdifConstants.RejectionCategory.NO_CATEGORY_MATCH
            )

    class TestBaseDNFiltering:
        """Test base DN filtering."""

        def test_filter_by_base_dn_includes_matching(self) -> None:
            """Test filter_by_base_dn() includes entries under base DN."""
            entries = [
                TestCategorization.Factories.create_user_entry(
                    f"cn=user1,{TestCategorization.Constants.DN_BASE}",
                ),
                TestCategorization.Factories.create_user_entry(
                    f"cn=user2,{TestCategorization.Constants.DN_BASE}",
                ),
            ]
            service = FlextLdifCategorization(
                base_dn=TestCategorization.Constants.DN_BASE,
            )
            # FlexibleCategories is a type alias, use the actual class
            categories = FlextModelsCollections.Categories[m.Entry]()
            categories[TestCategorization.Constants.CATEGORY_USERS] = entries
            filtered = service.filter_by_base_dn(categories)
            assert len(filtered[TestCategorization.Constants.CATEGORY_USERS]) == 2

        def test_filter_by_base_dn_excludes_outside_base(self) -> None:
            """Test filter_by_base_dn() excludes entries outside base DN."""
            entries = [
                TestCategorization.Factories.create_user_entry(
                    f"cn=user1,{TestCategorization.Constants.DN_BASE}",
                ),
                TestCategorization.Factories.create_user_entry(
                    "cn=user2,dc=other,dc=com",
                ),
            ]
            service = FlextLdifCategorization(
                base_dn=TestCategorization.Constants.DN_BASE,
            )
            # FlexibleCategories is a type alias, use the actual class
            categories = FlextModelsCollections.Categories[m.Entry]()
            categories[TestCategorization.Constants.CATEGORY_USERS] = entries
            filtered = service.filter_by_base_dn(categories)
            assert len(filtered[TestCategorization.Constants.CATEGORY_USERS]) == 1
            assert len(service.rejection_tracker["base_dn_filter"]) == 1

        def test_filter_by_base_dn_tracks_metadata(self) -> None:
            """Test filter_by_base_dn() tracks filter results in metadata."""
            entry = TestCategorization.Factories.create_user_entry()
            # Add processing_stats
            stats = m.EntryStatistics()
            metadata = m.QuirkMetadata(
                quirk_type=Filters.SERVER_RFC,
                processing_stats=stats,
            )
            entry_with_stats = entry.model_copy(update={"metadata": metadata})

            service = FlextLdifCategorization(
                base_dn=TestCategorization.Constants.DN_BASE,
            )
            # FlexibleCategories is a type alias, use the actual class
            categories = FlextModelsCollections.Categories[m.Entry]()
            categories[TestCategorization.Constants.CATEGORY_USERS] = [entry_with_stats]
            filtered = service.filter_by_base_dn(categories)
            filtered_entry = filtered[TestCategorization.Constants.CATEGORY_USERS][0]
            assert filtered_entry.metadata is not None
            assert filtered_entry.metadata.processing_stats is not None
            assert filtered_entry.metadata.processing_stats.was_filtered
            assert (
                FlextLdifConstants.FilterType.BASE_DN_FILTER
                in filtered_entry.metadata.processing_stats.filters_applied
            )

        def test_filter_by_base_dn_skips_schema_rejected(self) -> None:
            """Test filter_by_base_dn() skips schema and rejected categories."""
            schema_entry = TestCategorization.Factories.create_schema_entry()
            rejected_entry = self.create_entry(
                "cn=rejected,dc=example,dc=com",
                {c.Names.CN: [c.Values.TEST]},
            )
            service = FlextLdifCategorization(
                base_dn=TestCategorization.Constants.DN_BASE,
            )
            # FlexibleCategories is a type alias, use the actual class
            categories = FlextModelsCollections.Categories[m.Entry]()
            categories[TestCategorization.Constants.CATEGORY_SCHEMA] = [schema_entry]
            categories[TestCategorization.Constants.CATEGORY_REJECTED] = [
                rejected_entry,
            ]
            filtered = service.filter_by_base_dn(categories)
            assert len(filtered[TestCategorization.Constants.CATEGORY_SCHEMA]) == 1
            assert len(filtered[TestCategorization.Constants.CATEGORY_REJECTED]) == 1

        def test_filter_by_base_dn_no_base_dn_configured(self) -> None:
            """Test filter_by_base_dn() returns unchanged if no base DN."""
            entries = [TestCategorization.Factories.create_user_entry()]
            service = FlextLdifCategorization()
            # FlexibleCategories is a type alias, use the actual class
            categories = FlextModelsCollections.Categories[m.Entry]()
            categories[TestCategorization.Constants.CATEGORY_USERS] = entries
            filtered = service.filter_by_base_dn(categories)
            assert len(filtered[TestCategorization.Constants.CATEGORY_USERS]) == 1

    class TestSchemaOIDFiltering:
        """Test schema OID whitelist filtering."""

        def test_filter_schema_by_oids_allows_matching(self) -> None:
            """Test filter_schema_by_oids() allows matching OIDs."""
            entry = TestCategorization.Factories.create_schema_entry()
            service = FlextLdifCategorization(
                schema_whitelist_rules={
                    "allowed_attribute_oids": [OIDs.CN],
                },
            )
            result = service.filter_schema_by_oids([entry])
            filtered = self.assert_success(result)
            assert len(filtered) == 1

        def test_filter_schema_by_oids_filters_non_matching(self) -> None:
            """Test filter_schema_by_oids() filters non-matching OIDs."""
            entry = TestCategorization.Factories.create_schema_entry()
            service = FlextLdifCategorization(
                schema_whitelist_rules={
                    "allowed_attribute_oids": ["1.2.3.4"],  # Different OID
                },
            )
            result = service.filter_schema_by_oids([entry])
            filtered = self.assert_success(result)
            assert len(filtered) == 0

        def test_filter_schema_by_oids_no_rules_configured(self) -> None:
            """Test filter_schema_by_oids() returns all if no rules."""
            entry = TestCategorization.Factories.create_schema_entry()
            service = FlextLdifCategorization()
            result = service.filter_schema_by_oids([entry])
            filtered = self.assert_success(result)
            assert len(filtered) == 1

    class TestStaticMethods:
        """Test static methods."""

        def test_filter_categories_by_base_dn(self) -> None:
            """Test filter_categories_by_base_dn() static method."""
            entries = [
                TestCategorization.Factories.create_user_entry(
                    f"cn=user1,{TestCategorization.Constants.DN_BASE}",
                ),
                TestCategorization.Factories.create_user_entry(
                    "cn=user2,dc=other,dc=com",
                ),
            ]
            # FlexibleCategories is a type alias, use the actual class
            categories = FlextModelsCollections.Categories[m.Entry]()
            categories[TestCategorization.Constants.CATEGORY_USERS] = entries
            filtered = FlextLdifCategorization.filter_categories_by_base_dn(
                categories,
                TestCategorization.Constants.DN_BASE,
            )
            assert len(filtered[TestCategorization.Constants.CATEGORY_USERS]) == 1
            assert len(filtered[TestCategorization.Constants.CATEGORY_REJECTED]) == 1

    class TestDependencyInjection:
        """Test FlextLdifServer dependency injection."""

        def test_uses_injected_server_registry(self) -> None:
            """Test service uses injected server registry."""
            custom_registry = FlextLdifServer()
            service = FlextLdifCategorization(
                server_type=TestCategorization.Constants.SERVER_RFC,
                server_registry=custom_registry,
            )
            entry = TestCategorization.Factories.create_user_entry()
            category, _reason = service.categorize_entry(entry)
            assert category in {
                TestCategorization.Constants.CATEGORY_USERS,
                TestCategorization.Constants.CATEGORY_REJECTED,
            }

        def test_uses_global_server_registry_by_default(self) -> None:
            """Test service uses global server registry by default."""
            service = FlextLdifCategorization(
                server_type=TestCategorization.Constants.SERVER_RFC,
            )
            entry = TestCategorization.Factories.create_user_entry()
            category, _reason = service.categorize_entry(entry)
            assert category in {
                TestCategorization.Constants.CATEGORY_USERS,
                TestCategorization.Constants.CATEGORY_REJECTED,
            }

    class TestProperties:
        """Test service properties."""

        def test_rejection_tracker_property(self) -> None:
            """Test rejection_tracker property."""
            service = FlextLdifCategorization()
            tracker = service.rejection_tracker
            assert isinstance(tracker, dict)
            assert "invalid_dn_rfc4514" in tracker
            assert "base_dn_filter" in tracker
            assert "categorization_rejected" in tracker

        def test_forbidden_attributes_property(self) -> None:
            """Test forbidden_attributes property."""
            forbidden = ["creatorsName", "modifiersName"]
            service = FlextLdifCategorization(forbidden_attributes=forbidden)
            assert service.forbidden_attributes == forbidden

        def test_forbidden_objectclasses_property(self) -> None:
            """Test forbidden_objectclasses property."""
            forbidden = ["blockedClass"]
            service = FlextLdifCategorization(forbidden_objectclasses=forbidden)
            assert service.forbidden_objectclasses == forbidden

        def test_base_dn_property(self) -> None:
            """Test base_dn property."""
            base_dn = TestCategorization.Constants.DN_BASE
            service = FlextLdifCategorization(base_dn=base_dn)
            assert service.base_dn == base_dn

        def test_schema_whitelist_rules_property(self) -> None:
            """Test schema_whitelist_rules property."""
            rules = m.WhitelistRules(allowed_attribute_oids=[OIDs.CN])
            service = FlextLdifCategorization(schema_whitelist_rules=rules)
            assert service.schema_whitelist_rules == rules

    class TestEdgeCases:
        """Test edge cases and error handling."""

        def test_categorize_empty_entries(self) -> None:
            """Test categorize_entries() with empty list."""
            service = FlextLdifCategorization()
            result = service.categorize_entries([])
            categories = self.assert_success(result)
            # Check all predefined categories are empty
            assert len(categories[FlextLdifConstants.Categories.SCHEMA]) == 0
            assert len(categories[FlextLdifConstants.Categories.HIERARCHY]) == 0
            assert len(categories[FlextLdifConstants.Categories.USERS]) == 0
            assert len(categories[FlextLdifConstants.Categories.GROUPS]) == 0
            assert len(categories[FlextLdifConstants.Categories.ACL]) == 0
            assert len(categories[FlextLdifConstants.Categories.REJECTED]) == 0

        def test_filter_by_base_dn_empty_categories(self) -> None:
            """Test filter_by_base_dn() with empty categories."""
            service = FlextLdifCategorization(
                base_dn=TestCategorization.Constants.DN_BASE,
            )
            # FlexibleCategories is a type alias, use the actual class
            categories = FlextModelsCollections.Categories[m.Entry]()
            filtered = service.filter_by_base_dn(categories)
            # Check all predefined categories are empty
            assert len(filtered[FlextLdifConstants.Categories.SCHEMA]) == 0
            assert len(filtered[FlextLdifConstants.Categories.HIERARCHY]) == 0
            assert len(filtered[FlextLdifConstants.Categories.USERS]) == 0
            assert len(filtered[FlextLdifConstants.Categories.GROUPS]) == 0
            assert len(filtered[FlextLdifConstants.Categories.ACL]) == 0
            assert len(filtered[FlextLdifConstants.Categories.REJECTED]) == 0

        def test_execute_returns_empty_categories(self) -> None:
            """Test execute() returns empty categories."""
            service = FlextLdifCategorization()
            result = service.execute()
            categories = self.assert_success(result)
            # Check all predefined categories are empty
            assert len(categories[FlextLdifConstants.Categories.SCHEMA]) == 0
            assert len(categories[FlextLdifConstants.Categories.HIERARCHY]) == 0
            assert len(categories[FlextLdifConstants.Categories.USERS]) == 0
            assert len(categories[FlextLdifConstants.Categories.GROUPS]) == 0
            assert len(categories[FlextLdifConstants.Categories.ACL]) == 0
            assert len(categories[FlextLdifConstants.Categories.REJECTED]) == 0
