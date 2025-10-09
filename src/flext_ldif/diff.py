"""LDIF Diff Utility for comparing LDAP data across quirks.

Provides semantic comparison of:
- ACLs (Access Control Lists) between any server quirks
- Schemas (attributes and objectClasses) between any server quirks
- Entries (directory entries) between any server quirks

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from flext_core import FlextResult
from pydantic import BaseModel

from flext_ldif.typings import FlextLdifTypes


@dataclass(frozen=True)
class DiffResult:
    """Result of a diff operation showing changes between two datasets."""

    added: list[dict[str, Any]]
    """Items present in target but not in source."""

    removed: list[dict[str, Any]]
    """Items present in source but not in target."""

    modified: list[dict[str, Any]]
    """Items present in both but with different values."""

    unchanged: list[dict[str, Any]]
    """Items that are identical in both datasets."""

    @property
    def has_changes(self) -> bool:
        """Check if there are any differences."""
        return bool(self.added or self.removed or self.modified)

    @property
    def total_changes(self) -> int:
        """Total number of changes (added + removed + modified)."""
        return len(self.added) + len(self.removed) + len(self.modified)

    def summary(self) -> str:
        """Get human-readable summary of changes."""
        if not self.has_changes:
            return "No differences found"

        parts = []
        if self.added:
            parts.append(f"{len(self.added)} added")
        if self.removed:
            parts.append(f"{len(self.removed)} removed")
        if self.modified:
            parts.append(f"{len(self.modified)} modified")
        if self.unchanged:
            parts.append(f"{len(self.unchanged)} unchanged")

        return ", ".join(parts)


class FlextLdifDiff(BaseModel):
    """LDIF diff utility for semantic comparison across any quirk types.

    Compares parsed LDIF data at semantic level, not string comparison.
    Works with data from any LDAP server quirk (OID, OUD, OpenLDAP, etc.).

    Example:
        diff_tool = FlextLdifDiff()

        # Compare schemas
        result = diff_tool.diff_schemas(oid_schemas, oud_schemas)
        print(result.summary())

        # Compare ACLs
        acl_result = diff_tool.diff_acls(oid_acls, oud_acls)
        for added in acl_result.added:
            print(f"New ACL: {added}")

    """

    def diff_attributes(
        self,
        source_attrs: list[FlextLdifTypes.Dict],
        target_attrs: list[FlextLdifTypes.Dict],
    ) -> FlextResult[DiffResult]:
        """Compare attribute definitions between two quirk types.

        Compares attributes by OID (primary) or NAME (fallback).
        Identifies added, removed, and modified attributes.

        Args:
            source_attrs: List of parsed attribute dictionaries from source quirk
            target_attrs: List of parsed attribute dictionaries from target quirk

        Returns:
            FlextResult[DiffResult] with comparison results

        Example:
            oid_attrs = [oid_quirk.parse_attribute(attr).unwrap() for attr in oid_attr_defs]
            oud_attrs = [oud_quirk.parse_attribute(attr).unwrap() for attr in oud_attr_defs]
            result = diff_tool.diff_attributes(oid_attrs, oud_attrs)

        """
        try:
            # Build lookup maps by OID (preferred) and NAME (fallback)
            source_map = {
                attr.get("oid") or attr.get("name"): attr for attr in source_attrs
            }
            target_map = {
                attr.get("oid") or attr.get("name"): attr for attr in target_attrs
            }

            added = []
            removed = []
            modified = []
            unchanged = []

            # Find added and modified attributes
            for key, target_attr in target_map.items():
                if key not in source_map:
                    added.append({
                        "oid": target_attr.get("oid"),
                        "name": target_attr.get("name"),
                        "desc": target_attr.get("desc"),
                        "syntax": target_attr.get("syntax"),
                    })
                else:
                    source_attr = source_map[key]
                    if self._attributes_differ(source_attr, target_attr):
                        modified.append({
                            "oid": target_attr.get("oid"),
                            "name": target_attr.get("name"),
                            "source": source_attr,
                            "target": target_attr,
                            "changes": self._get_attribute_changes(source_attr, target_attr),
                        })
                    else:
                        unchanged.append({
                            "oid": target_attr.get("oid"),
                            "name": target_attr.get("name"),
                        })

            # Find removed attributes
            for key, source_attr in source_map.items():
                if key not in target_map:
                    removed.append({
                        "oid": source_attr.get("oid"),
                        "name": source_attr.get("name"),
                        "desc": source_attr.get("desc"),
                    })

            return FlextResult[DiffResult].ok(
                DiffResult(
                    added=added,
                    removed=removed,
                    modified=modified,
                    unchanged=unchanged,
                )
            )

        except Exception as e:
            return FlextResult[DiffResult].fail(f"Attribute diff failed: {e}")

    def diff_objectclasses(
        self,
        source_ocs: list[FlextLdifTypes.Dict],
        target_ocs: list[FlextLdifTypes.Dict],
    ) -> FlextResult[DiffResult]:
        """Compare objectClass definitions between two quirk types.

        Compares objectClasses by OID (primary) or NAME (fallback).
        Identifies added, removed, and modified objectClasses.

        Args:
            source_ocs: List of parsed objectClass dictionaries from source quirk
            target_ocs: List of parsed objectClass dictionaries from target quirk

        Returns:
            FlextResult[DiffResult] with comparison results

        """
        try:
            # Build lookup maps
            source_map = {oc.get("oid") or oc.get("name"): oc for oc in source_ocs}
            target_map = {oc.get("oid") or oc.get("name"): oc for oc in target_ocs}

            added = []
            removed = []
            modified = []
            unchanged = []

            # Find added and modified objectClasses
            for key, target_oc in target_map.items():
                if key not in source_map:
                    added.append({
                        "oid": target_oc.get("oid"),
                        "name": target_oc.get("name"),
                        "kind": target_oc.get("kind"),
                        "sup": target_oc.get("sup"),
                    })
                else:
                    source_oc = source_map[key]
                    if self._objectclasses_differ(source_oc, target_oc):
                        modified.append({
                            "oid": target_oc.get("oid"),
                            "name": target_oc.get("name"),
                            "source": source_oc,
                            "target": target_oc,
                            "changes": self._get_objectclass_changes(source_oc, target_oc),
                        })
                    else:
                        unchanged.append({
                            "oid": target_oc.get("oid"),
                            "name": target_oc.get("name"),
                        })

            # Find removed objectClasses
            for key, source_oc in source_map.items():
                if key not in target_map:
                    removed.append({
                        "oid": source_oc.get("oid"),
                        "name": source_oc.get("name"),
                        "kind": source_oc.get("kind"),
                    })

            return FlextResult[DiffResult].ok(
                DiffResult(
                    added=added,
                    removed=removed,
                    modified=modified,
                    unchanged=unchanged,
                )
            )

        except Exception as e:
            return FlextResult[DiffResult].fail(f"ObjectClass diff failed: {e}")

    def diff_schemas(
        self,
        source_schema: FlextLdifTypes.Dict,
        target_schema: FlextLdifTypes.Dict,
    ) -> FlextResult[DiffResult]:
        """Compare complete schemas (attributes + objectClasses) between quirks.

        Provides high-level schema comparison including both attributes and objectClasses.

        Args:
            source_schema: Parsed schema dict with 'attributes' and 'objectclasses' keys
            target_schema: Parsed schema dict with 'attributes' and 'objectclasses' keys

        Returns:
            FlextResult[DiffResult] with combined comparison results

        """
        try:
            source_attrs_raw = source_schema.get("attributes", [])
            target_attrs_raw = target_schema.get("attributes", [])
            source_ocs_raw = source_schema.get("objectclasses", [])
            target_ocs_raw = target_schema.get("objectclasses", [])

            # Type narrowing for mypy
            source_attrs: list[FlextLdifTypes.Dict] = (
                source_attrs_raw if isinstance(source_attrs_raw, list) else []
            )
            target_attrs: list[FlextLdifTypes.Dict] = (
                target_attrs_raw if isinstance(target_attrs_raw, list) else []
            )
            source_ocs: list[FlextLdifTypes.Dict] = (
                source_ocs_raw if isinstance(source_ocs_raw, list) else []
            )
            target_ocs: list[FlextLdifTypes.Dict] = (
                target_ocs_raw if isinstance(target_ocs_raw, list) else []
            )

            # Diff attributes
            attr_result = self.diff_attributes(source_attrs, target_attrs)
            if not attr_result.is_success:
                return attr_result

            # Diff objectClasses
            oc_result = self.diff_objectclasses(source_ocs, target_ocs)
            if not oc_result.is_success:
                return oc_result

            # Combine results
            attr_diff = attr_result.unwrap()
            oc_diff = oc_result.unwrap()

            combined_added = [
                {"type": "attribute", **item} for item in attr_diff.added
            ] + [{"type": "objectclass", **item} for item in oc_diff.added]

            combined_removed = [
                {"type": "attribute", **item} for item in attr_diff.removed
            ] + [{"type": "objectclass", **item} for item in oc_diff.removed]

            combined_modified = [
                {"type": "attribute", **item} for item in attr_diff.modified
            ] + [{"type": "objectclass", **item} for item in oc_diff.modified]

            combined_unchanged = [
                {"type": "attribute", **item} for item in attr_diff.unchanged
            ] + [{"type": "objectclass", **item} for item in oc_diff.unchanged]

            return FlextResult[DiffResult].ok(
                DiffResult(
                    added=combined_added,
                    removed=combined_removed,
                    modified=combined_modified,
                    unchanged=combined_unchanged,
                )
            )

        except Exception as e:
            return FlextResult[DiffResult].fail(f"Schema diff failed: {e}")

    def diff_acls(
        self,
        source_acls: list[FlextLdifTypes.Dict],
        target_acls: list[FlextLdifTypes.Dict],
    ) -> FlextResult[DiffResult]:
        """Compare ACL definitions between two quirk types.

        Compares ACLs semantically, understanding that different quirks
        may have different ACL formats (OID orclaci vs OUD ACI).

        Args:
            source_acls: List of parsed ACL dictionaries from source quirk
            target_acls: List of parsed ACL dictionaries from target quirk

        Returns:
            FlextResult[DiffResult] with comparison results

        """
        try:
            # ACL comparison is complex because formats differ significantly
            # between quirks (OID orclaci vs OUD ACI). We compare semantically
            # by extracting common elements: target, permissions, subjects

            source_normalized = [self._normalize_acl(acl) for acl in source_acls]
            target_normalized = [self._normalize_acl(acl) for acl in target_acls]

            # Build lookup by semantic signature
            source_map = {self._acl_signature(acl): acl for acl in source_normalized}
            target_map = {self._acl_signature(acl): acl for acl in target_normalized}

            added = []
            removed = []
            modified = []
            unchanged = []

            # Find added and modified ACLs
            for sig, target_acl in target_map.items():
                if sig not in source_map:
                    added.append(target_acl)
                else:
                    source_acl = source_map[sig]
                    if self._acls_differ(source_acl, target_acl):
                        modified.append({
                            "signature": sig,
                            "source": source_acl,
                            "target": target_acl,
                        })
                    else:
                        unchanged.append(target_acl)

            # Find removed ACLs
            for sig, source_acl in source_map.items():
                if sig not in target_map:
                    removed.append(source_acl)

            return FlextResult[DiffResult].ok(
                DiffResult(
                    added=added,
                    removed=removed,
                    modified=modified,
                    unchanged=unchanged,
                )
            )

        except Exception as e:
            return FlextResult[DiffResult].fail(f"ACL diff failed: {e}")

    def diff_entries(
        self,
        source_entries: list[FlextLdifTypes.Dict],
        target_entries: list[FlextLdifTypes.Dict],
    ) -> FlextResult[DiffResult]:
        """Compare directory entries between two quirk types.

        Compares entries by DN, identifying added, removed, and modified entries.

        Args:
            source_entries: List of parsed entry dictionaries from source quirk
            target_entries: List of parsed entry dictionaries from target quirk

        Returns:
            FlextResult[DiffResult] with comparison results

        """
        try:
            # Build lookup maps by DN
            source_map = {
                self._normalize_dn(str(entry.get("dn", ""))): entry
                for entry in source_entries
            }
            target_map = {
                self._normalize_dn(str(entry.get("dn", ""))): entry
                for entry in target_entries
            }

            added = []
            removed = []
            modified = []
            unchanged = []

            # Find added and modified entries
            for dn, target_entry in target_map.items():
                if dn not in source_map:
                    added.append({
                        "dn": target_entry.get("dn"),
                        "objectClass": target_entry.get("objectClass"),
                    })
                else:
                    source_entry = source_map[dn]
                    if self._entries_differ(source_entry, target_entry):
                        modified.append({
                            "dn": target_entry.get("dn"),
                            "source": source_entry,
                            "target": target_entry,
                            "changes": self._get_entry_changes(source_entry, target_entry),
                        })
                    else:
                        unchanged.append({"dn": target_entry.get("dn")})

            # Find removed entries
            for dn, source_entry in source_map.items():
                if dn not in target_map:
                    removed.append({
                        "dn": source_entry.get("dn"),
                        "objectClass": source_entry.get("objectClass"),
                    })

            return FlextResult[DiffResult].ok(
                DiffResult(
                    added=added,
                    removed=removed,
                    modified=modified,
                    unchanged=unchanged,
                )
            )

        except Exception as e:
            return FlextResult[DiffResult].fail(f"Entry diff failed: {e}")

    # Private helper methods

    def _attributes_differ(
        self, attr1: FlextLdifTypes.Dict, attr2: FlextLdifTypes.Dict
    ) -> bool:
        """Check if two attributes have semantic differences."""
        # Compare key fields, ignoring metadata and quirk-specific fields
        keys_to_compare = ["name", "desc", "syntax", "equality", "single_value", "sup"]
        return any(attr1.get(k) != attr2.get(k) for k in keys_to_compare)

    def _get_attribute_changes(
        self, attr1: FlextLdifTypes.Dict, attr2: FlextLdifTypes.Dict
    ) -> list[str]:
        """Get list of changed fields between two attributes."""
        changes = []
        keys_to_compare = ["name", "desc", "syntax", "equality", "single_value", "sup"]
        for key in keys_to_compare:
            val1 = attr1.get(key)
            val2 = attr2.get(key)
            if val1 != val2:
                changes.append(f"{key}: {val1} → {val2}")
        return changes

    def _objectclasses_differ(
        self, oc1: FlextLdifTypes.Dict, oc2: FlextLdifTypes.Dict
    ) -> bool:
        """Check if two objectClasses have semantic differences."""
        keys_to_compare = ["name", "desc", "kind", "sup", "must", "may"]
        return any(oc1.get(k) != oc2.get(k) for k in keys_to_compare)

    def _get_objectclass_changes(
        self, oc1: FlextLdifTypes.Dict, oc2: FlextLdifTypes.Dict
    ) -> list[str]:
        """Get list of changed fields between two objectClasses."""
        changes = []
        keys_to_compare = ["name", "desc", "kind", "sup", "must", "may"]
        for key in keys_to_compare:
            val1 = oc1.get(key)
            val2 = oc2.get(key)
            if val1 != val2:
                changes.append(f"{key}: {val1} → {val2}")
        return changes

    def _normalize_acl(self, acl: FlextLdifTypes.Dict) -> FlextLdifTypes.Dict:
        """Normalize ACL to common format for comparison."""
        # Extract semantic elements regardless of quirk format
        normalized: FlextLdifTypes.Dict = {
            "type": acl.get("type", "unknown"),
            "format": acl.get("format", "unknown"),
        }

        # Extract target
        if "target" in acl:
            normalized["target"] = acl["target"]
        elif "targetattr" in acl:
            normalized["target"] = f"attr:{acl['targetattr']}"

        # Extract permissions/operations
        permissions: set[str] = set()
        if "by_clauses" in acl:
            by_clauses = acl["by_clauses"]
            if isinstance(by_clauses, list):
                for clause in by_clauses:
                    if isinstance(clause, dict) and "permissions" in clause:
                        perms = clause["permissions"]
                        if isinstance(perms, list):
                            permissions.update(str(p) for p in perms)
        elif "permissions" in acl:
            acl_perms = acl["permissions"]
            if isinstance(acl_perms, list):
                for perm in acl_perms:
                    if isinstance(perm, dict) and "operations" in perm:
                        ops = perm["operations"]
                        if isinstance(ops, list):
                            permissions.update(str(op) for op in ops)

        if permissions:
            normalized["permissions"] = sorted(permissions)

        return normalized

    def _acl_signature(self, acl: FlextLdifTypes.Dict) -> str:
        """Generate unique signature for ACL based on semantic content."""
        perms = acl.get("permissions", [])
        perms_str = ",".join(sorted(perms)) if isinstance(perms, list) else ""
        parts = [
            str(acl.get("target", "")),
            perms_str,
        ]
        return "|".join(parts)

    def _acls_differ(
        self, acl1: FlextLdifTypes.Dict, acl2: FlextLdifTypes.Dict
    ) -> bool:
        """Check if two ACLs have semantic differences."""
        perms1 = acl1.get("permissions", [])
        perms2 = acl2.get("permissions", [])
        perms1_set = set(perms1) if isinstance(perms1, list) else set()
        perms2_set = set(perms2) if isinstance(perms2, list) else set()
        return acl1.get("target") != acl2.get("target") or perms1_set != perms2_set

    def _normalize_dn(self, dn: str) -> str:
        """Normalize DN for comparison (lowercase, remove spaces)."""
        return dn.lower().replace(" ", "")

    def _entries_differ(
        self, entry1: FlextLdifTypes.Dict, entry2: FlextLdifTypes.Dict
    ) -> bool:
        """Check if two entries have differences."""
        # Compare all attributes except metadata and server_type
        exclude_keys = {"_metadata", "server_type", "dn"}
        keys1 = {k for k in entry1 if k not in exclude_keys}
        keys2 = {k for k in entry2 if k not in exclude_keys}

        if keys1 != keys2:
            return True

        # Compare attribute values
        for key in keys1:
            val1 = entry1[key]
            val2 = entry2[key]
            # Normalize list vs single value
            if isinstance(val1, list) and not isinstance(val2, list):
                val2 = [val2]
            elif not isinstance(val1, list) and isinstance(val2, list):
                val1 = [val1]
            if val1 != val2:
                return True

        return False

    def _get_entry_changes(
        self, entry1: FlextLdifTypes.Dict, entry2: FlextLdifTypes.Dict
    ) -> list[str]:
        """Get list of changed attributes between two entries."""
        changes = []
        all_keys = set(entry1.keys()) | set(entry2.keys())
        exclude_keys = {"_metadata", "server_type", "dn"}

        for key in sorted(all_keys - exclude_keys):
            val1 = entry1.get(key)
            val2 = entry2.get(key)
            if val1 != val2:
                changes.append(f"{key}: {val1} → {val2}")

        return changes


__all__ = ["DiffResult", "FlextLdifDiff"]
