"""FLEXT-LDIF Entry Transformer Service - Entry transformation operations.

This service handles transformation of entries including:
- Removing attributes from entries
- Removing objectClasses from entries
- Preserving removed values in metadata

Extracted from FlextLdifFilters to follow Single Responsibility Principle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifEntryTransformer(
    FlextService[FlextLdifTypes.Models.ServiceResponseTypes],
):
    """Service for entry transformation operations.

    Provides methods for:
    - Removing attributes from entries (with metadata tracking)
    - Removing objectClasses from entries (with validation)
    - Preserving removed values in entry metadata

    Example:
        transformer = FlextLdifEntryTransformer()

        # Remove temporary attributes
        result = transformer.remove_attributes(
            entry,
            attributes=["nsAccountLock", "userPassword"]
        )
        modified_entry = result.unwrap()

        # Remove obsolete objectClasses
        result = transformer.remove_objectclasses(
            entry,
            objectclasses=["obsoleteClass", "deprecatedClass"]
        )

    """

    def execute(
        self,
        **_kwargs: object,
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
        """Execute method required by FlextService abstract base class.

        This service provides specific methods (remove_attributes, remove_objectclasses)
        rather than a generic execute operation.

        Args:
            **_kwargs: Ignored parameters for FlextService protocol compatibility

        Returns:
            FlextResult with not implemented error

        """
        return FlextResult.fail(
            "FlextLdifEntryTransformer does not support generic execute(). Use specific methods instead.",
        )

    def remove_attributes(
        self,
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove attributes from entry, preserving removed values in metadata.

        Removes specified attributes from entry and stores them in
        metadata.removed_attributes for audit trail.

        Args:
            entry: Entry to modify
            attributes: List of attribute names to remove (case-insensitive)

        Returns:
            FlextResult with modified entry (removed attributes stored in metadata)

        Example:
            result = transformer.remove_attributes(
                entry,
                attributes=["nsAccountLock", "userPassword"]
            )
            if result.is_success:
                modified_entry = result.unwrap()
                # Removed attributes are in modified_entry.metadata.removed_attributes

        """
        try:
            if entry.attributes is None:
                error_msg = f"Entry {FlextLdifUtilities.DN.get_dn_value(entry.dn)} has no attributes"
                return FlextResult[FlextLdifModels.Entry].fail(error_msg)

            blocked_lower = {attr.lower() for attr in attributes}

            # Store removed attributes with their values in metadata BEFORE filtering
            removed_attrs_with_values = {
                key: value
                for key, value in entry.attributes.attributes.items()
                if key.lower() in blocked_lower
            }

            # Filter attributes
            filtered_attrs_dict = {
                key: value
                for key, value in entry.attributes.attributes.items()
                if key.lower() not in blocked_lower
            }

            new_attributes = FlextLdifModels.LdifAttributes(
                attributes=filtered_attrs_dict,
                metadata=entry.attributes.metadata,
            )

            # Check DN is not None before creating entry
            if not entry.dn:
                return FlextResult[FlextLdifModels.Entry].fail("Entry has no DN")

            # Create entry with removed attributes metadata, preserving original metadata
            entry_result = FlextLdifModels.Entry.create(
                dn=entry.dn,
                attributes=new_attributes,
                metadata=entry.metadata,  # Preserve metadata including processing_stats
            )

            if entry_result.is_failure:
                # Convert domain Entry result to public Entry result
                return FlextResult[FlextLdifModels.Entry].fail(
                    entry_result.error or "Unknown error",
                )

            new_entry_domain = entry_result.unwrap()
            # Type narrowing: Entry.create returns Domain.Entry, but we need Models.Entry
            # Since Models.Entry extends Domain.Entry, we can safely use it
            if isinstance(new_entry_domain, FlextLdifModels.Entry):
                new_entry = new_entry_domain
            else:
                # Convert domain Entry to public Entry if needed
                # This should not happen in practice, but handle it defensively
                error_msg = (
                    "Entry.create() returned domain Entry instead of public Entry"
                )
                return FlextResult[FlextLdifModels.Entry].fail(error_msg)

            # RFC Compliance: Store removed attributes in metadata.removed_attributes
            if removed_attrs_with_values:
                # Update metadata with removed attributes
                new_removed = {
                    **entry.metadata.removed_attributes,
                    **removed_attrs_with_values,
                }
                new_metadata = new_entry.metadata.model_copy(
                    update={"removed_attributes": new_removed},
                )
                new_entry = new_entry.model_copy(update={"metadata": new_metadata})

                # Track in statistics (only names) if statistics exist
                if new_entry.metadata.processing_stats:
                    for attr_name in removed_attrs_with_values:
                        new_entry.metadata.processing_stats.track_attribute_change(
                            attr_name,
                            "removed",
                        )

            return FlextResult[FlextLdifModels.Entry].ok(new_entry)

        except (ValueError, TypeError, AttributeError) as e:
            error_msg = f"Failed to remove attributes: {e}"
            return FlextResult[FlextLdifModels.Entry].fail(error_msg)

    def remove_objectclasses(
        self,
        entry: FlextLdifModels.Entry,
        objectclasses: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove objectClasses from entry.

        Removes specified objectClasses from entry, validating that at least
        one objectClass remains (RFC requirement).

        Args:
            entry: Entry to modify
            objectclasses: List of objectClass names to remove (case-insensitive)

        Returns:
            FlextResult with modified entry

        Example:
            result = transformer.remove_objectclasses(
                entry,
                objectclasses=["obsoleteClass"]
            )
            if result.is_success:
                modified_entry = result.unwrap()

        """
        try:
            if entry.attributes is None:
                error_msg = f"Entry {FlextLdifUtilities.DN.get_dn_value(entry.dn)} has no attributes"
                return FlextResult[FlextLdifModels.Entry].fail(error_msg)

            blocked_lower = {oc.lower() for oc in objectclasses}

            oc_values = entry.get_attribute_values(
                FlextLdifConstants.DictKeys.OBJECTCLASS,
            )
            if not oc_values:
                return FlextResult[FlextLdifModels.Entry].ok(entry)

            filtered_ocs = [oc for oc in oc_values if oc.lower() not in blocked_lower]
            if not filtered_ocs:
                return FlextResult[FlextLdifModels.Entry].fail(
                    "All objectClasses would be removed",
                )

            new_attrs_dict = dict(entry.attributes.attributes)
            new_attrs_dict[FlextLdifConstants.DictKeys.OBJECTCLASS] = filtered_ocs

            new_attributes = FlextLdifModels.LdifAttributes(
                attributes=new_attrs_dict,
                metadata=entry.attributes.metadata,
            )

            # Check DN is not None before creating entry
            if not entry.dn:
                return FlextResult[FlextLdifModels.Entry].fail("Entry has no DN")

            # Create entry with filtered objectClasses, preserving original metadata
            entry_result = FlextLdifModels.Entry.create(
                dn=entry.dn,
                attributes=new_attributes,
                metadata=entry.metadata,  # Preserve metadata including processing_stats
            )

            if entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    entry_result.error or "Unknown error",
                )

            new_entry_domain = entry_result.unwrap()
            # Type narrowing: Entry.create returns Domain.Entry, but we need Models.Entry
            if isinstance(new_entry_domain, FlextLdifModels.Entry):
                return FlextResult[FlextLdifModels.Entry].ok(new_entry_domain)

            # Convert domain Entry to public Entry if needed
            error_msg = "Entry.create() returned domain Entry instead of public Entry"
            return FlextResult[FlextLdifModels.Entry].fail(error_msg)

        except (ValueError, TypeError, AttributeError) as e:
            error_msg = f"Failed to remove objectClasses: {e}"
            return FlextResult[FlextLdifModels.Entry].fail(error_msg)


__all__ = ["FlextLdifEntryTransformer"]
