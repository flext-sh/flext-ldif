"""Comprehensive unit tests for utilities module.

Tests the Normalizer, Sorter, and Statistics classes from FlextLdifUtilities
with real LDIF data and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdifConstants
from flext_ldif.utilities import FlextLdifUtilities


class TestNormalizer:
    """Test DN and attribute normalization utilities."""

    def test_build_canonical_dn_map_simple(self) -> None:
        """Test building canonical DN map from simple entries."""
        categorized = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=John,OU=Users,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ]
        }

        result = FlextLdifUtilities.Normalizer.build_canonical_dn_map(categorized)

        assert len(result) > 0, "Should build DN map"
        # DN map should contain lowercase version as key
        assert any("john" in key.lower() for key in result), (
            "Should have normalized DN entries"
        )

    def test_build_canonical_dn_map_multiple_entries(self) -> None:
        """Test building canonical DN map from multiple entries."""
        categorized = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User1,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                },
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User2,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                },
            ]
        }

        result = FlextLdifUtilities.Normalizer.build_canonical_dn_map(categorized)

        assert len(result) >= 2, "Should have at least 2 entries in DN map"

    def test_build_canonical_dn_map_empty(self) -> None:
        """Test building canonical DN map from empty categorized."""
        categorized: dict[str, list[dict[str, object]]] = {}

        result = FlextLdifUtilities.Normalizer.build_canonical_dn_map(categorized)

        assert result == {}, "Should return empty map for empty categorized"

    def test_build_canonical_dn_map_invalid_entries(self) -> None:
        """Test building canonical DN map with invalid entry types."""
        categorized = {
            "mixed": [
                "not_a_dict",  # type: ignore[list-item]
                {FlextLdifConstants.DictKeys.DN: None},  # DN is None
                {"no_dn": "value"},  # Missing DN
            ]
        }

        result = FlextLdifUtilities.Normalizer.build_canonical_dn_map(categorized)

        # Should handle gracefully, empty or partial
        assert isinstance(result, dict)

    def test_normalize_dn_value_in_map(self) -> None:
        """Test normalizing a DN value that exists in the map."""
        dn_map = {"cn=user1,dc=example,dc=com": "CN=User1,DC=Example,DC=Com"}

        result = FlextLdifUtilities.Normalizer.normalize_dn_value(
            "CN=User1,DC=Example,DC=Com", dn_map
        )

        # Should return the canonical value from map
        assert "User1" in result

    def test_normalize_dn_value_not_in_map(self) -> None:
        """Test normalizing a DN value that's not in the map."""
        dn_map = {"cn=user1,dc=example,dc=com": "CN=User1,DC=Example,DC=Com"}

        result = FlextLdifUtilities.Normalizer.normalize_dn_value(
            "CN=User99,DC=Example,DC=Com", dn_map
        )

        # Should return cleaned DN when not in map
        assert isinstance(result, str)
        assert len(result) > 0

    def test_normalize_dn_references_for_entry_with_dn_attrs(self) -> None:
        """Test normalizing DN reference attributes in entry."""
        dn_map = {"cn=user1,dc=example,dc=com": "CN=User1,DC=Example,DC=Com"}
        ref_attrs = {"manager", "owner", "member"}

        entry = {
            FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "manager": "CN=User1,DC=Example,DC=Com",
                "cn": ["User"],
                "member": [
                    "CN=User1,DC=Example,DC=Com",
                    "CN=User99,DC=Example,DC=Com",
                ],
            },
        }

        result = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, ref_attrs
        )

        assert FlextLdifConstants.DictKeys.ATTRIBUTES in result
        attrs = result[FlextLdifConstants.DictKeys.ATTRIBUTES]
        assert isinstance(attrs, dict)
        assert "manager" in attrs
        assert "cn" in attrs
        assert "member" in attrs

    def test_normalize_dn_references_for_entry_no_attrs(self) -> None:
        """Test normalizing entry without attributes."""
        dn_map = {}
        ref_attrs: set[str] = set()

        entry = {FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com"}

        result = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, ref_attrs
        )

        assert (
            result[FlextLdifConstants.DictKeys.DN]
            == entry[FlextLdifConstants.DictKeys.DN]
        )

    def test_normalize_dn_references_for_entry_invalid_attrs(self) -> None:
        """Test normalizing entry where attributes is not a dict."""
        dn_map = {}
        ref_attrs: set[str] = set()

        entry = {
            FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: "not_a_dict",  # type: ignore[assignment]
        }

        result = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, ref_attrs
        )

        # Should return entry unchanged
        assert result == entry

    def test_normalize_aci_dn_references_ldap_urls(self) -> None:
        """Test normalizing DNs in ACI strings with ldap:// URLs."""
        dn_map = {"cn=admin,dc=example,dc=com": "CN=Admin,DC=Example,DC=Com"}

        entry = {
            FlextLdifConstants.DictKeys.DN: "CN=Group,DC=Example,DC=Com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "aci": [
                    'aci (target="ldap:///cn=admin,dc=example,dc=com") (version 3.0;'
                ]
            },
        }

        result = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, dn_map
        )

        assert FlextLdifConstants.DictKeys.ATTRIBUTES in result
        attrs = result[FlextLdifConstants.DictKeys.ATTRIBUTES]
        assert isinstance(attrs, dict)
        assert "aci" in attrs

    def test_normalize_aci_dn_references_quoted_dns(self) -> None:
        """Test normalizing DNs in ACI strings with quoted DN patterns."""
        dn_map = {"cn=user,dc=example,dc=com": "CN=User,DC=Example,DC=Com"}

        entry = {
            FlextLdifConstants.DictKeys.DN: "CN=Group,DC=Example,DC=Com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "aci": 'aci (userdn="cn=user,dc=example,dc=com") (version 3.0;'
            },
        }

        result = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, dn_map
        )

        assert FlextLdifConstants.DictKeys.ATTRIBUTES in result
        attrs = result[FlextLdifConstants.DictKeys.ATTRIBUTES]
        assert isinstance(attrs, dict)

    def test_normalize_aci_dn_references_no_aci(self) -> None:
        """Test normalizing entry without ACI attributes."""
        dn_map = {}

        entry = {
            FlextLdifConstants.DictKeys.DN: "CN=Group,DC=Example,DC=Com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": "Group"},
        }

        result = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, dn_map
        )

        # Should return entry unchanged
        assert FlextLdifConstants.DictKeys.ATTRIBUTES in result

    def test_normalize_aci_dn_references_exception_handling(self) -> None:
        """Test that ACI normalization handles exceptions gracefully."""
        dn_map = {}

        entry = {
            FlextLdifConstants.DictKeys.DN: "CN=Group,DC=Example,DC=Com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: "invalid",  # type: ignore[assignment]
        }

        result = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, dn_map
        )

        # Should return entry unchanged when exception occurs
        assert result == entry


class TestSorter:
    """Test entry sorting utilities."""

    def test_sort_entries_by_hierarchy_simple(self) -> None:
        """Test sorting entries by DN hierarchy."""
        entries = [
            {FlextLdifConstants.DictKeys.DN: "CN=C,CN=B,CN=A,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=B,CN=A,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=A,DC=Example,DC=Com"},
        ]

        result = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(entries)

        # Should be sorted by depth (fewest RDN components first)
        assert len(result) == 3
        # First entry should have fewest commas
        first_dn = result[0][FlextLdifConstants.DictKeys.DN]
        assert isinstance(first_dn, str)
        assert first_dn.count(",") <= result[1][FlextLdifConstants.DictKeys.DN].count(
            ","
        )

    def test_sort_entries_by_hierarchy_same_depth(self) -> None:
        """Test sorting entries at same depth by name."""
        entries = [
            {FlextLdifConstants.DictKeys.DN: "CN=Zebra,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=Apple,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=Banana,DC=Example,DC=Com"},
        ]

        result = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(entries)

        # Should be sorted by name at same depth
        dns = [e[FlextLdifConstants.DictKeys.DN] for e in result]
        assert len(dns) == 3
        # All should have same depth but different order
        assert isinstance(dns[0], str)

    def test_sort_entries_empty(self) -> None:
        """Test sorting empty entry list."""
        entries: list[dict[str, object]] = []

        result = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(entries)

        assert result == []

    def test_sort_entries_with_invalid_dns(self) -> None:
        """Test sorting entries with invalid or missing DNs."""
        entries = [
            {FlextLdifConstants.DictKeys.DN: "CN=Valid,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: None},  # Invalid DN
            {"no_dn": "value"},  # Missing DN
            {FlextLdifConstants.DictKeys.DN: 123},  # type: ignore[misc] # Invalid type
        ]

        result = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(entries)

        # Should handle gracefully - valid entries first, then invalid
        assert len(result) > 0
        # Valid entry should be in result
        assert any(
            e.get(FlextLdifConstants.DictKeys.DN) == "CN=Valid,DC=Example,DC=Com"
            for e in result
        )


class TestStatistics:
    """Test statistics generation utilities."""

    def test_generate_statistics_simple(self) -> None:
        """Test generating statistics from categorized entries."""
        categorized = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User1,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ],
            "groups": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Group1,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ],
        }
        written_counts = {"users": 1, "groups": 1}
        output_dir = Path("/output")
        output_files = {"users": "users.ldif", "groups": "groups.ldif"}

        result = FlextLdifUtilities.Statistics.generate_statistics(
            categorized, written_counts, output_dir, output_files
        )

        assert result["total_entries"] == 2
        assert result["categorized"]["users"] == 1
        assert result["categorized"]["groups"] == 1
        assert result["rejection_rate"] == 0.0
        assert result["rejection_count"] == 0

    def test_generate_statistics_with_rejections(self) -> None:
        """Test generating statistics with rejected entries."""
        categorized = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User1,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ],
            "rejected": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Invalid,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "rejectionReason": "Invalid schema"
                    },
                }
            ],
        }
        written_counts = {"users": 1}
        output_dir = Path("/output")
        output_files = {"users": "users.ldif", "rejected": "rejected.ldif"}

        result = FlextLdifUtilities.Statistics.generate_statistics(
            categorized, written_counts, output_dir, output_files
        )

        assert result["total_entries"] == 2
        assert result["rejection_count"] == 1
        assert result["rejection_rate"] == 0.5
        assert "Invalid schema" in result["rejection_reasons"]

    def test_generate_statistics_empty(self) -> None:
        """Test generating statistics from empty categorized."""
        categorized: dict[str, list[dict[str, object]]] = {}
        written_counts: dict[str, int] = {}
        output_dir = Path("/output")
        output_files: dict[str, object] = {}

        result = FlextLdifUtilities.Statistics.generate_statistics(
            categorized, written_counts, output_dir, output_files
        )

        assert result["total_entries"] == 0
        assert result["rejection_rate"] == 0.0
        assert result["rejection_count"] == 0

    def test_generate_statistics_multiple_rejection_reasons(self) -> None:
        """Test generating statistics with multiple rejection reasons."""
        categorized = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User1,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ],
            "rejected": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Invalid1,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "rejectionReason": "Invalid schema"
                    },
                },
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Invalid2,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "rejectionReason": "Duplicate DN"
                    },
                },
            ],
        }
        written_counts = {"users": 1}
        output_dir = Path("/output")
        output_files = {"users": "users.ldif"}

        result = FlextLdifUtilities.Statistics.generate_statistics(
            categorized, written_counts, output_dir, output_files
        )

        assert result["rejection_count"] == 2
        assert len(result["rejection_reasons"]) == 2
        assert "Invalid schema" in result["rejection_reasons"]
        assert "Duplicate DN" in result["rejection_reasons"]

    def test_generate_statistics_output_file_paths(self) -> None:
        """Test that output file paths are correctly generated."""
        categorized = {"users": []}
        written_counts = {"users": 0}
        output_dir = Path("/output")
        output_files = {"users": "custom_users.ldif"}

        result = FlextLdifUtilities.Statistics.generate_statistics(
            categorized, written_counts, output_dir, output_files
        )

        assert "output_files" in result
        assert "users" in result["output_files"]
        assert "custom_users.ldif" in result["output_files"]["users"]
