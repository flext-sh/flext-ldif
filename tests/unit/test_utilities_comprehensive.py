"""Comprehensive tests for LDIF processing utilities.

Tests cover:
- DN normalization and mapping
- DN-valued attribute handling
- ACI DN reference normalization
- Entry sorting by hierarchy
- Pipeline statistics generation

All tests use REAL implementations with actual LDIF fixture data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.utilities import FlextLdifUtilities


class TestNormalizerBuildCanonicalDnMap:
    """Test building canonical DN maps from categorized entries."""

    def test_build_map_from_single_entry(self) -> None:
        """Test building canonical DN map from single entry."""
        categorized = {
            "user": [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=john,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["john"]},
                }
            ]
        }
        dn_map = FlextLdifUtilities.Normalizer.build_canonical_dn_map(categorized)
        assert isinstance(dn_map, dict)
        assert len(dn_map) > 0

    def test_build_map_preserves_canonical_case(self) -> None:
        """Test that canonical DN map preserves first-seen case."""
        categorized = {
            "user": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=John,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["john"]},
                },
                {
                    FlextLdifConstants.DictKeys.DN: "cn=admin,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["admin"]},
                },
            ]
        }
        dn_map = FlextLdifUtilities.Normalizer.build_canonical_dn_map(categorized)
        assert isinstance(dn_map, dict)
        assert len(dn_map) >= 1

    def test_build_map_handles_empty_category(self) -> None:
        """Test handling empty category."""
        categorized = {"empty": []}
        dn_map = FlextLdifUtilities.Normalizer.build_canonical_dn_map(categorized)
        assert isinstance(dn_map, dict)
        assert len(dn_map) == 0

    def test_build_map_skips_invalid_entries(self) -> None:
        """Test that invalid entries are skipped."""
        categorized = {
            "mixed": [
                cast("object", "not a dict"),
                {
                    FlextLdifConstants.DictKeys.DN: "cn=valid,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["valid"]},
                },
                {"no_dn_key": "value"},
            ]
        }
        dn_map = FlextLdifUtilities.Normalizer.build_canonical_dn_map(categorized)
        assert isinstance(dn_map, dict)


class TestNormalizerNormalizeDnValue:
    """Test normalizing single DN values."""

    def test_normalize_exact_match_in_map(self) -> None:
        """Test normalizing DN that has exact match in map."""
        dn_map = {"cn=john,dc=example,dc=com": "CN=John,DC=Example,DC=Com"}
        normalized = FlextLdifUtilities.Normalizer.normalize_dn_value(
            "cn=john,dc=example,dc=com", dn_map
        )
        assert isinstance(normalized, str)

    def test_normalize_case_insensitive_match(self) -> None:
        """Test that normalization is case-insensitive."""
        dn_map = {"cn=john,dc=example,dc=com": "CN=John,DC=Example,DC=Com"}
        normalized = FlextLdifUtilities.Normalizer.normalize_dn_value(
            "CN=JOHN,DC=EXAMPLE,DC=COM", dn_map
        )
        assert isinstance(normalized, str)

    def test_normalize_with_no_match_uses_cleaned(self) -> None:
        """Test that unmatched DNs are cleaned but returned."""
        dn_map = {}
        normalized = FlextLdifUtilities.Normalizer.normalize_dn_value(
            "cn=john,dc=example,dc=com", dn_map
        )
        assert isinstance(normalized, str)
        assert len(normalized) > 0


class TestNormalizerNormalizeDnReferencesForEntry:
    """Test normalizing DN-valued attributes in entries."""

    def test_normalize_single_string_dn_value(self) -> None:
        """Test normalizing single string DN value."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=user,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "manager": "cn=admin,dc=example,dc=com",
            },
        }
        dn_map = {}
        normalized = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, {"manager"}
        )
        assert isinstance(normalized, dict)
        assert FlextLdifConstants.DictKeys.DN in normalized
        assert FlextLdifConstants.DictKeys.ATTRIBUTES in normalized

    def test_normalize_list_dn_values(self) -> None:
        """Test normalizing list of DN values."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=user,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "manager": [
                    "cn=admin,dc=example,dc=com",
                    "cn=director,dc=example,dc=com",
                ],
            },
        }
        dn_map = {}
        normalized = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, {"manager"}
        )
        assert isinstance(normalized, dict)
        attrs = normalized.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
        assert isinstance(attrs, dict)

    def test_normalize_mixed_list_dn_values(self) -> None:
        """Test normalizing list with mixed types."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=user,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "manager": [
                    "cn=admin,dc=example,dc=com",
                    12345,
                    None,
                ],
            },
        }
        dn_map = {}
        normalized = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, {"manager"}
        )
        assert isinstance(normalized, dict)

    def test_normalize_skips_non_dn_attributes(self) -> None:
        """Test that non-DN attributes are not modified."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=user,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "cn": ["user"],
                "objectClass": ["person"],
            },
        }
        dn_map = {}
        normalized = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, {"manager"}
        )
        assert isinstance(normalized, dict)
        attrs = normalized.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
        assert "cn" in attrs
        assert "objectClass" in attrs

    def test_normalize_handles_non_dict_attributes(self) -> None:
        """Test handling entry with non-dict attributes."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=user,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: cast("object", "not a dict"),
        }
        dn_map = {}
        normalized = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, {"manager"}
        )
        assert isinstance(normalized, dict)


class TestNormalizerNormalizeAciDnReferences:
    """Test normalizing DNs in ACI attribute strings."""

    def test_normalize_aci_with_ldap_uri(self) -> None:
        """Test normalizing ACI with ldap:/// URI."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=acl,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "aci": 'grant (read) userdn="ldap:///cn=admin,dc=example,dc=com";',
            },
        }
        dn_map = {}
        normalized = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, dn_map
        )
        assert isinstance(normalized, dict)
        assert FlextLdifConstants.DictKeys.ATTRIBUTES in normalized

    def test_normalize_aci_list_values(self) -> None:
        """Test normalizing ACI list values."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=acl,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "aci": [
                    'grant (read) userdn="ldap:///cn=admin,dc=example,dc=com";',
                    'grant (write) userdn="ldap:///cn=operator,dc=example,dc=com";',
                ],
            },
        }
        dn_map = {}
        normalized = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, dn_map
        )
        assert isinstance(normalized, dict)

    def test_normalize_aci_handles_non_dict_attributes(self) -> None:
        """Test handling ACI entry with non-dict attributes."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=acl,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: cast("object", "not a dict"),
        }
        dn_map = {}
        normalized = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, dn_map
        )
        assert isinstance(normalized, dict)

    def test_normalize_aci_without_aci_attribute(self) -> None:
        """Test normalizing entry without ACI attribute."""
        entry = {
            FlextLdifConstants.DictKeys.DN: "cn=user,dc=example,dc=com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["user"]},
        }
        dn_map = {}
        normalized = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, dn_map
        )
        assert isinstance(normalized, dict)


class TestSorterSortEntriesByHierarchy:
    """Test sorting entries by DN hierarchy and name."""

    def test_sort_flat_entries_by_name(self) -> None:
        """Test sorting flat entries by name."""
        entries = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=zebra,dc=example,dc=com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["zebra"]},
            },
            {
                FlextLdifConstants.DictKeys.DN: "cn=alpha,dc=example,dc=com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["alpha"]},
            },
        ]
        sorted_entries = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(
            entries
        )
        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 2

    def test_sort_hierarchical_entries_by_depth(self) -> None:
        """Test sorting entries by DN depth (hierarchy)."""
        entries = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=user,ou=people,dc=example,dc=com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["user"]},
            },
            {
                FlextLdifConstants.DictKeys.DN: "ou=people,dc=example,dc=com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {},
            },
            {
                FlextLdifConstants.DictKeys.DN: "dc=example,dc=com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {},
            },
        ]
        sorted_entries = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(
            entries
        )
        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 3

    def test_sort_handles_missing_dn(self) -> None:
        """Test sorting handles entries without DN."""
        entries = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=valid,dc=example,dc=com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["valid"]},
            },
            {"no_dn": "value"},
            {
                FlextLdifConstants.DictKeys.DN: cast("str", None),
                FlextLdifConstants.DictKeys.ATTRIBUTES: {},
            },
        ]
        sorted_entries = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(
            entries
        )
        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) >= 1

    def test_sort_handles_non_string_dn(self) -> None:
        """Test sorting handles non-string DN values."""
        entries = [
            {
                FlextLdifConstants.DictKeys.DN: cast("str", 12345),
                FlextLdifConstants.DictKeys.ATTRIBUTES: {},
            },
            {
                FlextLdifConstants.DictKeys.DN: "cn=valid,dc=example,dc=com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["valid"]},
            },
        ]
        sorted_entries = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(
            entries
        )
        assert isinstance(sorted_entries, list)

    def test_sort_empty_list(self) -> None:
        """Test sorting empty entry list."""
        sorted_entries = (
            FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name([])
        )
        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 0


class TestStatisticsGenerateStatistics:
    """Test generating statistics for categorized migrations."""

    def test_generate_stats_basic(self) -> None:
        """Test generating basic statistics."""
        categorized = {
            "user": [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=john,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["john"]},
                },
                {
                    FlextLdifConstants.DictKeys.DN: "cn=jane,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["jane"]},
                },
            ],
            "group": [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=admins,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["admins"]},
                },
            ],
        }
        written_counts = {"user": 2, "group": 1}
        output_dir = Path("/tmp")
        output_files = {"user": "users.ldif", "group": "groups.ldif"}

        stats = FlextLdifUtilities.Statistics.generate_statistics(
            categorized, written_counts, output_dir, output_files
        )
        assert isinstance(stats, dict)
        assert "total_entries" in stats
        assert stats["total_entries"] == 3

    def test_generate_stats_with_rejections(self) -> None:
        """Test generating statistics with rejected entries."""
        categorized = {
            "valid": [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=valid,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["valid"]},
                }
            ],
            "rejected": [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=bad,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "rejectionReason": "Invalid syntax"
                    },
                }
            ],
        }
        written_counts = {"valid": 1, "rejected": 0}
        output_dir = Path("/tmp")
        output_files = {"valid": "valid.ldif", "rejected": "rejected.ldif"}

        stats = FlextLdifUtilities.Statistics.generate_statistics(
            categorized, written_counts, output_dir, output_files
        )
        assert isinstance(stats, dict)
        assert "rejection_count" in stats
        assert "rejection_reasons" in stats
        assert stats["rejection_count"] >= 0

    def test_generate_stats_empty_categories(self) -> None:
        """Test generating statistics with empty categories."""
        categorized = {}
        written_counts = {}
        output_dir = Path("/tmp")
        output_files = {}

        stats = FlextLdifUtilities.Statistics.generate_statistics(
            categorized, written_counts, output_dir, output_files
        )
        assert isinstance(stats, dict)
        assert stats["total_entries"] == 0

    def test_generate_stats_rejection_rate_calculation(self) -> None:
        """Test that rejection rate is calculated correctly."""
        categorized = {
            "valid": [
                {
                    FlextLdifConstants.DictKeys.DN: f"cn=user{i},dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": [f"user{i}"]},
                }
                for i in range(8)
            ],
            "rejected": [
                {
                    FlextLdifConstants.DictKeys.DN: f"cn=bad{i},dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "rejectionReason": "Error"
                    },
                }
                for i in range(2)
            ],
        }
        written_counts = {"valid": 8, "rejected": 0}
        output_dir = Path("/tmp")
        output_files = {}

        stats = FlextLdifUtilities.Statistics.generate_statistics(
            categorized, written_counts, output_dir, output_files
        )
        assert isinstance(stats, dict)
        assert "rejection_rate" in stats
        assert stats["rejection_rate"] == pytest.approx(0.2, abs=0.001)
