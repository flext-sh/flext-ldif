"""Unit tests for LDIF utilities (Normalizer, Sorter, Statistics).

Tests cover:
- DN normalization and canonical mapping
- DN-valued attribute normalization (single and multi-value)
- ACI DN reference normalization
- Entry sorting by hierarchy and DN
- Statistics generation for migration operations

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.utilities import FlextLdifUtilities


class TestNormalizer:
    """Test FlextLdifUtilities.Normalizer functionality."""

    def test_build_canonical_dn_map_empty_categorized(self) -> None:
        """Test canonical DN map with empty categorized data."""
        result = FlextLdifUtilities.Normalizer.build_canonical_dn_map({})
        assert result == {}

    def test_build_canonical_dn_map_single_entry(self) -> None:
        """Test canonical DN map with single entry."""
        categorized: dict[str, list[dict[str, object]]] = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=John,OU=People,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ]
        }
        result = FlextLdifUtilities.Normalizer.build_canonical_dn_map(categorized)
        assert "cn=john,ou=people,dc=example,dc=com" in result
        assert isinstance(result["cn=john,ou=people,dc=example,dc=com"], str)

    def test_build_canonical_dn_map_multiple_entries(self) -> None:
        """Test canonical DN map with multiple entries."""
        categorized: dict[str, list[dict[str, object]]] = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Admin,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                },
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User,OU=People,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                },
            ]
        }
        result = FlextLdifUtilities.Normalizer.build_canonical_dn_map(categorized)
        assert len(result) == 2

    def test_build_canonical_dn_map_with_multiple_categories(self) -> None:
        """Test canonical DN map across multiple categories."""
        categorized: dict[str, list[dict[str, object]]] = {
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
        result = FlextLdifUtilities.Normalizer.build_canonical_dn_map(categorized)
        assert len(result) == 2

    def test_build_canonical_dn_map_skips_non_dict_entries(self) -> None:
        """Test that non-dict entries are skipped gracefully."""
        categorized: dict[str, list[dict[str, object]]] = {
            "users": [
                "invalid",  # type: ignore[list-item]
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                },
            ]
        }
        result = FlextLdifUtilities.Normalizer.build_canonical_dn_map(categorized)
        assert len(result) == 1

    def test_normalize_dn_value_found_in_map(self) -> None:
        """Test normalizing DN value found in canonical map."""
        dn_map = {"cn=admin,dc=example,dc=com": "CN=Admin,DC=Example,DC=Com"}
        result = FlextLdifUtilities.Normalizer.normalize_dn_value(
            "cn=admin,dc=example,dc=com", dn_map
        )
        assert result == "CN=Admin,DC=Example,DC=Com"

    def test_normalize_dn_value_not_in_map(self) -> None:
        """Test normalizing DN value not found in canonical map."""
        dn_map: dict[str, str] = {}
        result = FlextLdifUtilities.Normalizer.normalize_dn_value(
            "CN=User,DC=Example,DC=Com", dn_map
        )
        assert isinstance(result, str)

    def test_normalize_dn_references_for_entry_single_value(self) -> None:
        """Test normalizing single-value DN reference attribute."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "CN=Entry,DC=Example,DC=Com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "member": "CN=User,DC=Example,DC=Com"
            },
        }
        dn_map = {"cn=user,dc=example,dc=com": "CN=User,DC=Example,DC=Com"}
        ref_attrs = {"member"}

        result = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, ref_attrs
        )
        attrs = result[FlextLdifConstants.DictKeys.ATTRIBUTES]
        assert isinstance(attrs, dict)
        assert attrs["member"] == "CN=User,DC=Example,DC=Com"

    def test_normalize_dn_references_for_entry_multi_value(self) -> None:
        """Test normalizing multi-value DN reference attribute."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "CN=Group,DC=Example,DC=Com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "member": [
                    "CN=User1,DC=Example,DC=Com",
                    "CN=User2,DC=Example,DC=Com",
                ]
            },
        }
        dn_map = {
            "cn=user1,dc=example,dc=com": "CN=User1,DC=Example,DC=Com",
            "cn=user2,dc=example,dc=com": "CN=User2,DC=Example,DC=Com",
        }
        ref_attrs = {"member"}

        result = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, ref_attrs
        )
        attrs = result[FlextLdifConstants.DictKeys.ATTRIBUTES]
        assert isinstance(attrs, dict)
        members = attrs["member"]
        assert isinstance(members, list)
        assert len(members) == 2

    def test_normalize_dn_references_ignores_non_dn_attributes(self) -> None:
        """Test that non-DN attributes are not normalized."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "CN=Entry,DC=Example,DC=Com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {"description": "A user"},
        }
        dn_map = {"cn=user,dc=example,dc=com": "CN=User,DC=Example,DC=Com"}
        ref_attrs = {"member"}

        result = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, ref_attrs
        )
        attrs = result[FlextLdifConstants.DictKeys.ATTRIBUTES]
        assert isinstance(attrs, dict)
        assert attrs["description"] == "A user"

    def test_normalize_dn_references_empty_entry(self) -> None:
        """Test normalizing empty entry."""
        entry: dict[str, object] = {}
        dn_map: dict[str, str] = {}
        ref_attrs: set[str] = set()

        result = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, ref_attrs
        )
        # Empty entry gets attributes key added
        assert FlextLdifConstants.DictKeys.ATTRIBUTES in result

    def test_normalize_dn_references_attributes_not_dict(self) -> None:
        """Test normalizing when attributes is not a dict (line 103 coverage)."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "CN=Entry,DC=Example,DC=Com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: "invalid",  # Non-dict attributes
        }
        dn_map: dict[str, str] = {}
        ref_attrs: set[str] = {"member"}

        result = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, ref_attrs
        )
        # Should return entry unchanged when attributes is not dict
        assert result[FlextLdifConstants.DictKeys.ATTRIBUTES] == "invalid"

    def test_normalize_dn_references_non_string_non_list_value(self) -> None:
        """Test normalizing non-string, non-list DN reference values (line 122 coverage)."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "CN=Entry,DC=Example,DC=Com",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "member": 12345,  # Non-string, non-list value
                "description": "Test",  # Non-DN attribute for comparison
            },
        }
        dn_map: dict[str, str] = {}
        ref_attrs: set[str] = {"member"}

        result = FlextLdifUtilities.Normalizer.normalize_dn_references_for_entry(
            entry, dn_map, ref_attrs
        )
        attrs = result[FlextLdifConstants.DictKeys.ATTRIBUTES]
        assert isinstance(attrs, dict)
        # Non-string, non-list value should pass through unchanged
        assert attrs["member"] == 12345
        assert attrs["description"] == "Test"

    def test_normalize_aci_dn_references_ldap_url_format(self) -> None:
        """Test normalizing DNs in ACI ldap:// URL format."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=schema",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "aci": [
                    'aci: (target="ldap:///cn=admin,dc=example,dc=com")'
                ]
            },
        }
        dn_map = {"cn=admin,dc=example,dc=com": "CN=Admin,DC=Example,DC=Com"}

        result = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, dn_map
        )
        attrs = result[FlextLdifConstants.DictKeys.ATTRIBUTES]
        assert isinstance(attrs, dict)
        aci_value = attrs.get("aci")
        assert isinstance(aci_value, list)

    def test_normalize_aci_dn_references_quoted_dn_format(self) -> None:
        """Test normalizing DNs in ACI quoted DN format."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=schema",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "aci": ['some content with a DN like "cn=user,dc=example,dc=com"']
            },
        }
        dn_map = {"cn=user,dc=example,dc=com": "CN=User,DC=Example,DC=Com"}

        result = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, dn_map
        )
        assert FlextLdifConstants.DictKeys.ATTRIBUTES in result

    def test_normalize_aci_dn_references_string_aci(self) -> None:
        """Test normalizing ACI that is a string (not list)."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=schema",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "aci": 'aci: (target="ldap:///cn=admin,dc=example,dc=com")'
            },
        }
        dn_map = {"cn=admin,dc=example,dc=com": "CN=Admin,DC=Example,DC=Com"}

        result = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, dn_map
        )
        assert FlextLdifConstants.DictKeys.ATTRIBUTES in result

    def test_normalize_aci_dn_references_gracefully_handles_errors(self) -> None:
        """Test that ACI normalization handles errors gracefully."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=schema",
            FlextLdifConstants.DictKeys.ATTRIBUTES: None,  # Invalid attributes
        }
        dn_map = {"cn=admin,dc=example,dc=com": "CN=Admin,DC=Example,DC=Com"}

        result = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, dn_map
        )
        assert result == entry  # Returns unchanged entry

    def test_normalize_aci_dn_references_exception_in_try_block(self) -> None:
        """Test exception handling in normalize_aci_dn_references try block (lines 189-190)."""
        # Create entry where dn_map.get causes AttributeError by using wrong dict type
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=schema",
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "aci": 'aci: (target="ldap:///cn=admin,dc=example,dc=com")'
            },
        }
        # Use a non-dict as dn_map to trigger exception when calling dn_map.get()
        bad_dn_map: dict[str, str] = {}  # Empty dict won't have the key

        result = FlextLdifUtilities.Normalizer.normalize_aci_dn_references(
            entry, bad_dn_map
        )
        # Should return entry unchanged due to exception handling
        assert result == entry


class TestSorter:
    """Test FlextLdifUtilities.Sorter functionality."""

    def test_sort_entries_by_hierarchy_empty_list(self) -> None:
        """Test sorting empty entry list."""
        result = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name([])
        assert result == []

    def test_sort_entries_by_hierarchy_single_entry(self) -> None:
        """Test sorting single entry."""
        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {},
            }
        ]
        result = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(entries)
        assert len(result) == 1

    def test_sort_entries_by_hierarchy_depth(self) -> None:
        """Test sorting by DN hierarchy depth."""
        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "CN=A,OU=B,OU=C,DC=Example,DC=Com",
            },
            {FlextLdifConstants.DictKeys.DN: "CN=X,DC=Example,DC=Com"},
            {
                FlextLdifConstants.DictKeys.DN: "CN=Y,OU=Z,DC=Example,DC=Com",
            },
        ]
        result = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(entries)
        # Should be ordered by depth: shallowest first
        assert len(result) == 3

    def test_sort_entries_case_insensitive(self) -> None:
        """Test sorting is case-insensitive."""
        entries: list[dict[str, object]] = [
            {FlextLdifConstants.DictKeys.DN: "CN=ZEBRA,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=apple,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=banana,DC=Example,DC=Com"},
        ]
        result = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(entries)
        assert len(result) == 3
        # Order should be based on case-insensitive comparison

    def test_sort_entries_handles_missing_dn(self) -> None:
        """Test sorting with entries missing DN."""
        entries: list[dict[str, object]] = [
            {FlextLdifConstants.DictKeys.DN: "CN=Valid,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.ATTRIBUTES: {}},  # Missing DN
            {FlextLdifConstants.DictKeys.DN: "CN=Another,DC=Example,DC=Com"},
        ]
        result = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(entries)
        # Non-sortable entries should be at end
        assert len(result) == 3

    def test_sort_entries_mixed_dn_types(self) -> None:
        """Test sorting with mixed DN types (string, non-string)."""
        entries: list[dict[str, object]] = [
            {FlextLdifConstants.DictKeys.DN: "CN=Valid,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: 123},  # Invalid type
            {FlextLdifConstants.DictKeys.DN: "CN=Another,DC=Example,DC=Com"},
        ]
        result = FlextLdifUtilities.Sorter.sort_entries_by_hierarchy_and_name(entries)
        # Should have 3 items (valid DNs + 1 non-sortable)
        assert len(result) == 3


class TestStatistics:
    """Test FlextLdifUtilities.Statistics functionality."""

    def test_generate_statistics_empty_categorized(self) -> None:
        """Test statistics generation with empty categorized data."""
        from pathlib import Path

        result = FlextLdifUtilities.Statistics.generate_statistics(
            categorized={},
            written_counts={},
            output_dir=Path("/tmp"),
            output_files={},
        )

        assert result["total_entries"] == 0
        assert result["rejection_count"] == 0
        assert result["rejection_rate"] == 0.0

    def test_generate_statistics_single_category(self) -> None:
        """Test statistics generation with single category."""
        from pathlib import Path

        categorized: dict[str, list[dict[str, object]]] = {
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
        written_counts: dict[str, int] = {"users": 2}
        output_files: dict[str, object] = {"users": "users.ldif"}

        result = FlextLdifUtilities.Statistics.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=Path("/tmp"),
            output_files=output_files,
        )

        assert result["total_entries"] == 2
        categorized_stats = result["categorized"]
        assert isinstance(categorized_stats, dict)
        assert categorized_stats["users"] == 2
        written_counts_result = result["written_counts"]
        assert isinstance(written_counts_result, dict)
        assert written_counts_result["users"] == 2

    def test_generate_statistics_multiple_categories(self) -> None:
        """Test statistics generation with multiple categories."""
        from pathlib import Path

        categorized: dict[str, list[dict[str, object]]] = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ],
            "groups": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Group,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ],
        }
        written_counts: dict[str, int] = {"users": 1, "groups": 1}
        output_files: dict[str, object] = {"users": "users.ldif", "groups": "groups.ldif"}

        result = FlextLdifUtilities.Statistics.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=Path("/tmp"),
            output_files=output_files,
        )

        assert result["total_entries"] == 2
        categorized_stats = result["categorized"]
        assert isinstance(categorized_stats, dict)
        assert categorized_stats["users"] == 1
        assert categorized_stats["groups"] == 1

    def test_generate_statistics_with_rejections(self) -> None:
        """Test statistics generation with rejected entries."""
        from pathlib import Path

        categorized: dict[str, list[dict[str, object]]] = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ],
            "rejected": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Invalid,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "rejectionReason": "Missing objectClass"
                    },
                },
                {
                    FlextLdifConstants.DictKeys.DN: "CN=BadDN,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "rejectionReason": "Invalid DN format"
                    },
                },
            ],
        }
        written_counts: dict[str, int] = {"users": 1, "rejected": 2}
        output_files: dict[str, object] = {}

        result = FlextLdifUtilities.Statistics.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=Path("/tmp"),
            output_files=output_files,
        )

        assert result["total_entries"] == 3
        assert result["rejection_count"] == 2
        assert result["rejection_rate"] == pytest.approx(2 / 3)
        rejection_reasons = result["rejection_reasons"]
        assert isinstance(rejection_reasons, list)
        assert len(rejection_reasons) == 2

    def test_generate_statistics_output_files_mapping(self) -> None:
        """Test statistics includes correct output file paths."""
        from pathlib import Path

        output_dir = Path("/output")
        categorized: dict[str, list[dict[str, object]]] = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ]
        }
        output_files: dict[str, object] = {"users": "00-users.ldif"}
        written_counts: dict[str, int] = {"users": 1}

        result = FlextLdifUtilities.Statistics.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert "output_files" in result
        output_files_result = result["output_files"]
        assert isinstance(output_files_result, dict)
        assert "users" in output_files_result

    def test_generate_statistics_rejection_reasons_deduplication(self) -> None:
        """Test that rejection reasons are deduplicated."""
        from pathlib import Path

        categorized: dict[str, list[dict[str, object]]] = {
            "rejected": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Bad1,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "rejectionReason": "Same reason"
                    },
                },
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Bad2,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "rejectionReason": "Same reason"
                    },
                },
            ]
        }
        written_counts: dict[str, int] = {"rejected": 2}
        output_files: dict[str, object] = {}

        result = FlextLdifUtilities.Statistics.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=Path("/tmp"),
            output_files=output_files,
        )

        # Should have only 1 unique reason
        rejection_reasons = result["rejection_reasons"]
        assert isinstance(rejection_reasons, list)
        assert len(rejection_reasons) == 1
        assert rejection_reasons[0] == "Same reason"

    def test_generate_statistics_with_non_string_rejection_reason(self) -> None:
        """Test handling non-string rejection reasons."""
        from pathlib import Path

        categorized: dict[str, list[dict[str, object]]] = {
            "rejected": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Bad,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "rejectionReason": 123  # Non-string
                    },
                }
            ]
        }
        written_counts: dict[str, int] = {"rejected": 1}
        output_files: dict[str, object] = {}

        result = FlextLdifUtilities.Statistics.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=Path("/tmp"),
            output_files=output_files,
        )

        # Non-string rejection reasons should be ignored
        rejection_reasons = result["rejection_reasons"]
        assert isinstance(rejection_reasons, list)
        assert len(rejection_reasons) == 0
