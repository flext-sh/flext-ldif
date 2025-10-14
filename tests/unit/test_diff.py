"""Unit tests for LDIF diff functionality.

Tests semantic comparison of ACLs, schemas, and entries across quirk types.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

import pytest
from flext_core import FlextCore

from flext_ldif.diff import DiffResult, FlextLdifDiff
from flext_ldif.models import FlextLdifModels


class TestDiffResultDataclass:
    """Test DiffResult dataclass functionality."""

    def test_empty_diff_has_no_changes(self) -> None:
        """Test that empty diff reports no changes."""
        result = DiffResult(added=[], removed=[], modified=[], unchanged=[])
        assert not result.has_changes
        assert result.total_changes == 0
        assert result.summary() == "No differences found"

    def test_diff_with_changes(self) -> None:
        """Test diff result with changes."""
        result = DiffResult(
            added=[FlextLdifModels.DiffItem(key="oid_1.2.3", value={"oid": "1.2.3"})],
            removed=[FlextLdifModels.DiffItem(key="oid_4.5.6", value={"oid": "4.5.6"})],
            modified=[
                FlextLdifModels.DiffItem(key="oid_7.8.9", value={"oid": "7.8.9"})
            ],
            unchanged=[
                FlextLdifModels.DiffItem(key="oid_10.11.12", value={"oid": "10.11.12"})
            ],
        )
        assert result.has_changes
        assert result.total_changes == 3  # added + removed + modified
        summary = result.summary()
        assert "1 added" in summary
        assert "1 removed" in summary
        assert "1 modified" in summary
        assert "1 unchanged" in summary


class TestAttributeDiff:
    """Test attribute definition comparison."""

    @pytest.fixture
    def diff_tool(self) -> FlextLdifDiff:
        """Create diff tool instance."""
        return FlextLdifDiff()

    def test_identical_attributes(self, diff_tool: FlextLdifDiff) -> None:
        """Test that identical attributes show no differences."""
        attr1 = {
            "oid": "2.16.840.1.113894.1.1.1",
            "name": "orclguid",
            "desc": "Oracle GUID",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
        }
        attr2 = {
            "oid": "2.16.840.1.113894.1.1.1",
            "name": "orclguid",
            "desc": "Oracle GUID",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
        }

        result = diff_tool.diff_attributes(
            cast("list[FlextCore.Types.Dict]", [attr1]),
            cast("list[FlextCore.Types.Dict]", [attr2]),
        )
        assert result.is_success
        diff = result.unwrap()
        assert not diff.has_changes
        assert len(diff.unchanged) == 1

    def test_added_attribute(self, diff_tool: FlextLdifDiff) -> None:
        """Test detection of added attribute."""
        source_attrs: list[dict[str, str]] = []
        target_attrs = [
            {
                "oid": "2.16.840.1.113894.1.1.1",
                "name": "orclguid",
                "desc": "Oracle GUID",
            }
        ]

        result = diff_tool.diff_attributes(
            cast("list[FlextCore.Types.Dict]", source_attrs),
            cast("list[FlextCore.Types.Dict]", target_attrs),
        )
        assert result.is_success
        diff = result.unwrap()
        assert len(diff.added) == 1
        assert diff.added[0].value["oid"] == "2.16.840.1.113894.1.1.1"
        assert diff.added[0].value["name"] == "orclguid"

    def test_removed_attribute(self, diff_tool: FlextLdifDiff) -> None:
        """Test detection of removed attribute."""
        source_attrs = [
            {
                "oid": "2.16.840.1.113894.1.1.1",
                "name": "orclguid",
                "desc": "Oracle GUID",
            }
        ]
        target_attrs: list[dict[str, str]] = []

        result = diff_tool.diff_attributes(
            cast("list[FlextCore.Types.Dict]", source_attrs),
            cast("list[FlextCore.Types.Dict]", target_attrs),
        )
        assert result.is_success
        diff = result.unwrap()
        assert len(diff.removed) == 1
        assert diff.removed[0].value["oid"] == "2.16.840.1.113894.1.1.1"

    def test_modified_attribute(self, diff_tool: FlextLdifDiff) -> None:
        """Test detection of modified attribute."""
        source_attrs = [
            {
                "oid": "2.16.840.1.113894.1.1.1",
                "name": "orclguid",
                "desc": "Oracle GUID",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            }
        ]
        target_attrs = [
            {
                "oid": "2.16.840.1.113894.1.1.1",
                "name": "orclguid",
                "desc": "Modified Oracle GUID",  # Changed description
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            }
        ]

        result = diff_tool.diff_attributes(
            cast("list[FlextCore.Types.Dict]", source_attrs),
            cast("list[FlextCore.Types.Dict]", target_attrs),
        )
        assert result.is_success
        diff = result.unwrap()
        assert len(diff.modified) == 1
        assert "desc:" in diff.modified[0].value["changes"][0]


class TestObjectClassDiff:
    """Test objectClass definition comparison."""

    @pytest.fixture
    def diff_tool(self) -> FlextLdifDiff:
        """Create diff tool instance."""
        return FlextLdifDiff()

    def test_identical_objectclasses(self, diff_tool: FlextLdifDiff) -> None:
        """Test that identical objectClasses show no differences."""
        oc1 = {
            "oid": "2.16.840.1.113894.2.1.1",
            "name": "orclContainer",
            "desc": "Oracle Container",
            "kind": "STRUCTURAL",
            "sup": "top",
            "must": ["cn"],
        }
        oc2 = {
            "oid": "2.16.840.1.113894.2.1.1",
            "name": "orclContainer",
            "desc": "Oracle Container",
            "kind": "STRUCTURAL",
            "sup": "top",
            "must": ["cn"],
        }

        result = diff_tool.diff_objectclasses(
            cast("list[FlextCore.Types.Dict]", [oc1]),
            cast("list[FlextCore.Types.Dict]", [oc2])
        )
        assert result.is_success
        diff = result.unwrap()
        assert not diff.has_changes
        assert len(diff.unchanged) == 1

    def test_added_objectclass(self, diff_tool: FlextLdifDiff) -> None:
        """Test detection of added objectClass."""
        source_ocs: list[dict[str, str]] = []
        target_ocs = [
            {
                "oid": "2.16.840.1.113894.2.1.1",
                "name": "orclContainer",
                "kind": "STRUCTURAL",
            }
        ]

        result = diff_tool.diff_objectclasses(
            cast("list[FlextCore.Types.Dict]", source_ocs),
            cast("list[FlextCore.Types.Dict]", target_ocs)
        )
        assert result.is_success
        diff = result.unwrap()
        assert len(diff.added) == 1
        assert diff.added[0].value["name"] == "orclContainer"

    def test_modified_objectclass(self, diff_tool: FlextLdifDiff) -> None:
        """Test detection of modified objectClass."""
        source_ocs = [
            {
                "oid": "2.16.840.1.113894.2.1.1",
                "name": "orclContainer",
                "kind": "STRUCTURAL",
                "must": ["cn"],
            }
        ]
        target_ocs = [
            {
                "oid": "2.16.840.1.113894.2.1.1",
                "name": "orclContainer",
                "kind": "STRUCTURAL",
                "must": ["cn", "description"],  # Added required attribute
            }
        ]

        result = diff_tool.diff_objectclasses(
            cast("list[FlextCore.Types.Dict]", source_ocs),
            cast("list[FlextCore.Types.Dict]", target_ocs)
        )
        assert result.is_success
        diff = result.unwrap()
        assert len(diff.modified) == 1


class TestAclDiff:
    """Test ACL comparison across quirk types."""

    @pytest.fixture
    def diff_tool(self) -> FlextLdifDiff:
        """Create diff tool instance."""
        return FlextLdifDiff()

    def test_identical_acls(self, diff_tool: FlextLdifDiff) -> None:
        """Test that semantically identical ACLs show no differences."""
        # OID-style ACL
        acl1 = {
            "type": "standard",
            "target": "entry",
            "by_clauses": [{"subject": "*", "permissions": ["browse", "read"]}],
        }
        # Similar ACL (order may differ)
        acl2 = {
            "type": "standard",
            "target": "entry",
            "by_clauses": [{"subject": "*", "permissions": ["read", "browse"]}],
        }

        result = diff_tool.diff_acls(
            cast("list[FlextCore.Types.Dict]", [acl1]),
            cast("list[FlextCore.Types.Dict]", [acl2])
        )
        assert result.is_success
        diff = result.unwrap()
        # Should be detected as semantically similar
        assert not diff.has_changes or len(diff.unchanged) > 0

    def test_added_acl(self, diff_tool: FlextLdifDiff) -> None:
        """Test detection of added ACL."""
        source_acls: list[FlextCore.Types.Dict] = []
        target_acls = [
            {
                "type": "standard",
                "target": "entry",
                "by_clauses": [{"subject": "*", "permissions": ["browse"]}],
            }
        ]

        result = diff_tool.diff_acls(
            source_acls,
            cast("list[FlextCore.Types.Dict]", target_acls)
        )
        assert result.is_success
        diff = result.unwrap()
        assert len(diff.added) == 1

    def test_removed_acl(self, diff_tool: FlextLdifDiff) -> None:
        """Test detection of removed ACL."""
        source_acls = [
            {
                "type": "standard",
                "target": "entry",
                "by_clauses": [{"subject": "*", "permissions": ["browse"]}],
            }
        ]
        target_acls: list[FlextCore.Types.Dict] = []

        result = diff_tool.diff_acls(
            cast("list[FlextCore.Types.Dict]", source_acls),
            target_acls
        )
        assert result.is_success
        diff = result.unwrap()
        assert len(diff.removed) == 1

    def test_acl_with_different_permissions(self, diff_tool: FlextLdifDiff) -> None:
        """Test ACLs with different permissions are detected as different."""
        acl1 = {
            "type": "standard",
            "target": "entry",
            "by_clauses": [{"subject": "*", "permissions": ["browse"]}],
        }
        acl2 = {
            "type": "standard",
            "target": "entry",
            "by_clauses": [{"subject": "*", "permissions": ["write"]}],
        }

        result = diff_tool.diff_acls(
            cast("list[FlextCore.Types.Dict]", [acl1]),
            cast("list[FlextCore.Types.Dict]", [acl2])
        )
        assert result.is_success
        diff = result.unwrap()
        # Should detect as different ACLs (removed acl1, added acl2)
        assert diff.has_changes


class TestEntryDiff:
    """Test directory entry comparison."""

    @pytest.fixture
    def diff_tool(self) -> FlextLdifDiff:
        """Create diff tool instance."""
        return FlextLdifDiff()

    def test_identical_entries(self, diff_tool: FlextLdifDiff) -> None:
        """Test that identical entries show no differences."""
        entry1 = {
            "dn": "cn=test,dc=example,dc=com",
            "cn": ["test"],
            "objectClass": ["person"],
        }
        entry2 = {
            "dn": "cn=test,dc=example,dc=com",
            "cn": ["test"],
            "objectClass": ["person"],
        }

        result = diff_tool.diff_entries(
            cast("list[FlextCore.Types.Dict]", [entry1]),
            cast("list[FlextCore.Types.Dict]", [entry2])
        )
        assert result.is_success
        diff = result.unwrap()
        assert not diff.has_changes
        assert len(diff.unchanged) == 1

    def test_added_entry(self, diff_tool: FlextLdifDiff) -> None:
        """Test detection of added entry."""
        source_entries: list[FlextCore.Types.Dict] = []
        target_entries = [
            {
                "dn": "cn=test,dc=example,dc=com",
                "cn": ["test"],
                "objectClass": ["person"],
            }
        ]

        result = diff_tool.diff_entries(
            source_entries,
            cast("list[FlextCore.Types.Dict]", target_entries)
        )
        assert result.is_success
        diff = result.unwrap()
        assert len(diff.added) == 1
        assert diff.added[0].value["dn"] == "cn=test,dc=example,dc=com"

    def test_removed_entry(self, diff_tool: FlextLdifDiff) -> None:
        """Test detection of removed entry."""
        source_entries = [
            {
                "dn": "cn=test,dc=example,dc=com",
                "cn": ["test"],
                "objectClass": ["person"],
            }
        ]
        target_entries: list[FlextCore.Types.Dict] = []

        result = diff_tool.diff_entries(
            cast("list[FlextCore.Types.Dict]", source_entries),
            target_entries
        )
        assert result.is_success
        diff = result.unwrap()
        assert len(diff.removed) == 1

    def test_modified_entry(self, diff_tool: FlextLdifDiff) -> None:
        """Test detection of modified entry."""
        source_entries = [
            {
                "dn": "cn=test,dc=example,dc=com",
                "cn": ["test"],
                "mail": ["old@example.com"],
            }
        ]
        target_entries = [
            {
                "dn": "cn=test,dc=example,dc=com",
                "cn": ["test"],
                "mail": ["new@example.com"],  # Changed mail
            }
        ]

        result = diff_tool.diff_entries(
            cast("list[FlextCore.Types.Dict]", source_entries),
            cast("list[FlextCore.Types.Dict]", target_entries)
        )
        assert result.is_success
        diff = result.unwrap()
        assert len(diff.modified) == 1
        assert "mail:" in diff.modified[0].value["changes"][0]

    def test_dn_normalization(self, diff_tool: FlextLdifDiff) -> None:
        """Test that DN normalization handles case and spaces."""
        entry1 = {
            "dn": "CN=Test, DC=Example, DC=Com",
            "cn": ["test"],
        }
        entry2 = {
            "dn": "cn=test,dc=example,dc=com",  # Different case/spacing
            "cn": ["test"],
        }

        result = diff_tool.diff_entries(
            cast("list[FlextCore.Types.Dict]", [entry1]),
            cast("list[FlextCore.Types.Dict]", [entry2])
        )
        assert result.is_success
        diff = result.unwrap()
        # Should be detected as same entry despite DN formatting differences
        assert not diff.has_changes or len(diff.unchanged) == 1


class TestSchemaDiff:
    """Test complete schema comparison (attributes + objectClasses)."""

    @pytest.fixture
    def diff_tool(self) -> FlextLdifDiff:
        """Create diff tool instance."""
        return FlextLdifDiff()

    def test_schema_with_both_types(self, diff_tool: FlextLdifDiff) -> None:
        """Test schema diff with both attributes and objectClasses."""
        source_schema = {
            "attributes": [
                {
                    "oid": "1.2.3",
                    "name": "attr1",
                    "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                }
            ],
            "objectclasses": [{"oid": "4.5.6", "name": "oc1", "kind": "STRUCTURAL"}],
        }
        target_schema = {
            "attributes": [
                {
                    "oid": "1.2.3",
                    "name": "attr1",
                    "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                },
                {
                    "oid": "7.8.9",
                    "name": "attr2",
                    "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                },  # New attribute
            ],
            "objectclasses": [{"oid": "4.5.6", "name": "oc1", "kind": "STRUCTURAL"}],
        }

        result = diff_tool.diff_schemas(
            cast("FlextCore.Types.Dict", source_schema),
            cast("FlextCore.Types.Dict", target_schema)
        )
        assert result.is_success
        diff = result.unwrap()
        assert len(diff.added) == 1  # One new attribute
        assert diff.added[0].value["type"] == "attribute"
        assert diff.added[0].value["name"] == "attr2"


__all__ = [
    "TestAclDiff",
    "TestAttributeDiff",
    "TestDiffResultDataclass",
    "TestEntryDiff",
    "TestObjectClassDiff",
    "TestSchemaDiff",
]
