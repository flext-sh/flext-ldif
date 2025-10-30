"""Attribute filtering service for server-specific LDIF processing.

Centralizes OID attribute filtering logic for all entry types, replacing
scattered filtering implementations across multiple services.

RFC 4512 Compliance:
- Removes OID-specific attributes incompatible with target server
- Handles ACL attribute transformations (orclaci/orclentrylevelaci → aci)
- Preserves RFC-compliant entry structure

LAYER 5 PART D: Consolidation of duplicate filtering logic
- Previously scattered across entries.py, acl.py, migration.py, sync.py
- Now centralized in quirks system following metadata-driven pattern

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import ClassVar, override

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifAttributeFilterService(FlextService[dict[str, list[str] | str]]):
    """Service for filtering LDIF entry attributes based on server compatibility.

    Handles:
    1. Removal of OID-specific attributes not supported by OUD
    2. Metadata-driven ACL attribute transformation (OID → OUD format)
    3. Structural key filtering (attributes, metadata)
    4. Case-insensitive attribute matching

    Architecture:
    - Replaces _filter_oid_attributes() from entries.py (centralized)
    - Integrates with FlextLif quirks system for server-specific handling
    - Railway-oriented with FlextResult[T] pattern

    Responsibilities:
    - Accept entry with attributes and metadata
    - Check for ACL attribute presence and transformation status
    - Filter OID-specific attributes based on server type
    - Return cleaned attributes ready for LDAP operation

    """

    # Configuration - frozen to prevent runtime mutation
    # Normalize to lowercase for case-insensitive LDAP attribute matching
    OID_SPECIFIC_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        attr.lower() for attr in FlextLdifConstants.OperationalAttributes.OID_SPECIFIC
    )
    METADATA_KEYS: ClassVar[frozenset[str]] = frozenset({"attributes", "metadata"})
    ACL_ATTRIBUTES: ClassVar[tuple[str, ...]] = (
        "orclaci",  # OID ACL attribute (source format)
        "orclentrylevelaci",  # OID entry-level ACL (source format)
        "aci",  # Standard LDAP ACL (target format)
    )

    @override
    def __init__(self) -> None:
        """Initialize attribute filter service.

        Uses frozen configuration from FlextLdifConstants.
        No dependencies required - pure filtering logic.

        """
        super().__init__()
        self.logger.debug(
            "FlextLdifAttributeFilterService initialized",
            extra={
                "oid_attributes_count": len(self.OID_SPECIFIC_ATTRIBUTES),
                "metadata_keys": list(self.METADATA_KEYS),
                "acl_attributes": self.ACL_ATTRIBUTES,
            },
        )

    @override
    def execute(self) -> FlextResult[dict[str, list[str] | str]]:
        """Execute service - return status information."""
        return FlextResult[dict[str, list[str] | str]].ok({
            "service": "FlextLdifAttributeFilterService",
            "status": "ready",
            "oid_attributes": str(len(self.OID_SPECIFIC_ATTRIBUTES)),
        })

    def filter_entry_attributes(
        self,
        attributes: dict[str, list[str]],
        target_server_type: str = "oud",
        _metadata: dict[str, object] | None = None,
    ) -> FlextResult[dict[str, list[str]]]:
        """Filter entry attributes for target server type.

        Implements LAYER 5 PART D: Centralized attribute filtering

        Previously in entries.py::_filter_oid_attributes() - now unified

        Algorithm:
        1. Detect ACL attribute presence in entry (indicates transformation)
        2. If OUD format (aci present), remove source OID ACL attributes
        3. Filter all OID-specific attributes based on constants
        4. Exclude structural metadata keys
        5. Return cleaned attributes ready for LDAP sync

        Args:
            attributes: Dictionary of LDAP attributes to filter
            target_server_type: Target server ("oud", "openldap", etc.)

        Returns:
            FlextResult with filtered attributes dict

        Raises:
            Never - returns error in FlextResult, not exception

        Examples:
            >>> service = FlextLdifAttributeFilterService()
            >>> attrs = {"cn": "test", "orclaci": "grant...", "aci": "grant..."}
            >>> result = service.filter_entry_attributes(
            ...     attrs, target_server_type="oud"
            ... )
            >>> assert result.is_success
            >>> # Both orclaci and aci would be filtered/handled appropriately

        """
        try:
            # LAYER 5 PART C.3: Handle ACL attribute transformation
            # If entry has OUD format (aci present), remove source OID ACL attributes
            # to prevent duplicate ACL attributes after transformation
            oid_acl_attrs_to_remove: set[str] = set()
            has_oud_aci = any(attr.lower() == "aci" for attr in attributes)

            if has_oud_aci:
                # Entry has been transformed to OUD format
                # Remove source OID ACL attributes (orclaci, orclentrylevelaci)
                oid_acl_attrs_to_remove = {"orclaci", "orclentrylevelaci"}

            # Apply filtering with three conditions
            filtered = {
                attr: value
                for attr, value in attributes.items()
                if (
                    # Condition 1: Not in OID-specific attributes list
                    attr.lower() not in self.OID_SPECIFIC_ATTRIBUTES
                    # Condition 2: Not a structural metadata key
                    and attr.lower() not in self.METADATA_KEYS
                    # Condition 3: Not a duplicate ACL attribute (C.3 handling)
                    and attr.lower() not in oid_acl_attrs_to_remove
                )
            }

            self.logger.debug(
                "Entry attributes filtered",
                extra={
                    "input_count": len(attributes),
                    "output_count": len(filtered),
                    "removed_count": len(attributes) - len(filtered),
                    "has_aud_aci": has_oud_aci,
                    "target_server": target_server_type,
                },
            )

            return FlextResult[dict[str, list[str]]].ok(filtered)

        except (AttributeError, TypeError, KeyError) as e:
            error_msg = f"Attribute filtering failed: {type(e).__name__}: {e!s}"
            self.logger.exception(error_msg)
            return FlextResult[dict[str, list[str]]].fail(error_msg)

    def filter_entry(
        self,
        entry: FlextLdifModels.Entry,
        target_server_type: str = "oud",
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Filter attributes from a complete LDIF entry object.

        Convenience method for entry-based filtering (not dict-based).

        Args:
            entry: FlextLdifModels.Entry with attributes to filter
            target_server_type: Target server type

        Returns:
            FlextResult with modified entry (original unchanged)

        """
        try:
            # Extract attributes from entry
            attributes_dict = entry.attributes.attributes

            # Filter using main logic
            filter_result = self.filter_entry_attributes(
                attributes_dict,
                target_server_type=target_server_type,
            )

            if not filter_result.is_success:
                return FlextResult[FlextLdifModels.Entry].fail(filter_result.error)

            # Create new entry with filtered attributes
            filtered_attrs = filter_result.unwrap()

            # Reconstruct entry with filtered attributes
            # (keeping DN and other metadata unchanged)
            filtered_entry = FlextLdifModels.Entry(
                dn=entry.dn,
                attributes=FlextLdifModels.LdifAttributes(attributes=filtered_attrs),
                metadata=entry.metadata,
                acls=entry.acls,
                objectclasses=entry.objectclasses,
                entry_metadata=entry.entry_metadata,
                validation_metadata=entry.validation_metadata,
            )

            return FlextResult[FlextLdifModels.Entry].ok(filtered_entry)

        except (AttributeError, TypeError, KeyError) as e:
            error_msg = f"Entry filtering failed: {type(e).__name__}: {e!s}"
            self.logger.exception(error_msg)
            return FlextResult[FlextLdifModels.Entry].fail(error_msg)

    def should_filter_attribute(self, attribute_name: str) -> bool:
        """Quick check: should this attribute be filtered.

        Utility for pre-filtering or decision-making.

        Args:
            attribute_name: Name of attribute to check (case-insensitive)

        Returns:
            True if attribute should be filtered out, False if kept

        """
        lower_name = attribute_name.lower()
        return (
            lower_name in self.OID_SPECIFIC_ATTRIBUTES
            or lower_name in self.METADATA_KEYS
        )

    def get_filter_summary(
        self,
        attributes: dict[str, list[str] | str],
    ) -> dict[str, int]:
        """Get summary of what would be filtered.

        Useful for diagnostics and logging.

        Args:
            attributes: Dictionary to analyze

        Returns:
            Dict with counts of attributes by category

        """
        oid_attrs_count = 0
        metadata_count = 0
        kept_count = 0

        for attr in attributes:
            lower = attr.lower()
            if lower in self.OID_SPECIFIC_ATTRIBUTES:
                oid_attrs_count += 1
            elif lower in self.METADATA_KEYS:
                metadata_count += 1
            else:
                kept_count += 1

        return {
            "oid_specific_removed": oid_attrs_count,
            "metadata_removed": metadata_count,
            "kept": kept_count,
            "total_input": len(attributes),
        }
