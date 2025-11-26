"""FLEXT-LDIF Entry Transformer Service - Entry transformation operations.

This module provides entry transformation operations for flext-ldif including:
- Removing attributes from entries (with metadata preservation)
- Removing objectClasses from entries (with RFC compliance validation)
- Preserving removed values in entry metadata for audit trails

Scope: Entry transformation operations, metadata tracking, RFC compliance validation.
Modules: flext_ldif.services.entry_transformer

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
    """FLEXT-LDIF Entry Transformer Service.

    Provides entry transformation operations with metadata preservation and RFC compliance.
    Scope: Attribute removal, objectClass removal, metadata tracking for audit trails.
    """

    def execute(
        self,
        **_kwargs: object,
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
        """Execute method for FlextService protocol compatibility."""
        return FlextResult.fail(
            "Use specific methods: remove_attributes(), remove_objectclasses()",
        )

    def _validate_entry_dn(self, entry: FlextLdifModels.Entry) -> FlextResult[str]:
        """Validate entry has DN."""
        if not entry.dn:
            return FlextResult.fail("Entry has no DN")
        dn_value = FlextLdifUtilities.DN.get_dn_value(entry.dn)
        return FlextResult.ok(dn_value)

    def _validate_entry_attributes(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[bool]:
        """Validate entry has attributes."""
        if entry.attributes is None:
            dn_value = self._validate_entry_dn(entry).unwrap_or("unknown")
            return FlextResult.fail(f"Entry {dn_value} has no attributes")
        return FlextResult.ok(True)

    def _create_entry_with_metadata(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        attributes: FlextLdifModels.LdifAttributes,
        metadata: FlextLdifModels.QuirkMetadata | None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create entry preserving metadata."""
        entry_result = FlextLdifModels.Entry.create(
            dn=dn,
            attributes=attributes,
            metadata=metadata,
        )
        if entry_result.is_failure:
            error = entry_result.error or "Entry creation failed"
            return FlextResult.fail(error)

        new_entry = entry_result.unwrap()
        if not isinstance(new_entry, FlextLdifModels.Entry):
            return FlextResult.fail("Entry.create() returned wrong type")

        return FlextResult.ok(new_entry)

    def remove_attributes(
        self,
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove attributes from entry with metadata preservation."""
        try:
            # Validate entry
            if (attr_validation := self._validate_entry_attributes(entry)).is_failure:
                error = attr_validation.error or "Validation failed"
                return FlextResult.fail(error)
            if (dn_validation := self._validate_entry_dn(entry)).is_failure:
                error = dn_validation.error or "DN validation failed"
                return FlextResult.fail(error)

            blocked_lower = {attr.lower() for attr in attributes}

            # Store removed attributes with values for metadata
            removed_attrs = {
                key: value
                for key, value in entry.attributes.attributes.items()
                if key.lower() in blocked_lower
            }

            # Filter attributes
            filtered_attrs = {
                key: value
                for key, value in entry.attributes.attributes.items()
                if key.lower() not in blocked_lower
            }

            new_attributes = FlextLdifModels.LdifAttributes(
                attributes=filtered_attrs,
                metadata=entry.attributes.metadata,
            )

            # Create entry preserving metadata
            # DN is already validated by _validate_entry_dn() above
            # Use duck typing instead of isinstance to avoid class identity issues
            # between internal (FlextLdifModelsDomains) and public (FlextLdifModels) classes
            # Convert internal QuirkMetadata to public QuirkMetadata if needed
            metadata_public: FlextLdifModels.QuirkMetadata | None = None
            if entry.metadata is not None:
                metadata_public = FlextLdifModels.QuirkMetadata.model_validate(
                    entry.metadata.model_dump(),
                )
            # Convert internal DistinguishedName to public DistinguishedName if needed
            dn_public: str | FlextLdifModels.DistinguishedName
            if isinstance(entry.dn, FlextLdifModels.DistinguishedName):
                dn_public = entry.dn
            else:
                # Convert internal DN to public DN
                dn_public = FlextLdifModels.DistinguishedName.model_validate(
                    entry.dn.model_dump(),
                )
            entry_result = self._create_entry_with_metadata(
                dn=dn_public,
                attributes=new_attributes,
                metadata=metadata_public,
            )
            if entry_result.is_failure:
                error = entry_result.error or "Entry creation failed"
                return FlextResult.fail(error)

            new_entry = entry_result.unwrap()

            # Store removed attributes in metadata if any
            if removed_attrs:
                new_metadata = new_entry.metadata.model_copy(
                    update={
                        "removed_attributes": {
                            **entry.metadata.removed_attributes,
                            **removed_attrs,
                        }
                    },
                )
                new_entry = new_entry.model_copy(update={"metadata": new_metadata})

                # Track statistics
                if new_entry.metadata.processing_stats:
                    for attr_name in removed_attrs:
                        new_entry.metadata.processing_stats.track_attribute_change(
                            attr_name, "removed"
                        )

            return FlextResult.ok(new_entry)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to remove attributes: {e}")

    def remove_objectclasses(
        self,
        entry: FlextLdifModels.Entry,
        objectclasses: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove objectClasses from entry with RFC compliance validation."""
        try:
            # Validate entry
            if (attr_validation := self._validate_entry_attributes(entry)).is_failure:
                error = attr_validation.error or "Validation failed"
                return FlextResult.fail(error)
            if (dn_validation := self._validate_entry_dn(entry)).is_failure:
                error = dn_validation.error or "DN validation failed"
                return FlextResult.fail(error)

            blocked_lower = {oc.lower() for oc in objectclasses}

            oc_values = entry.get_attribute_values(
                FlextLdifConstants.DictKeys.OBJECTCLASS
            )
            if not oc_values:
                return FlextResult.ok(entry)

            filtered_ocs = [oc for oc in oc_values if oc.lower() not in blocked_lower]
            if not filtered_ocs:
                return FlextResult.fail("All objectClasses would be removed")

            # Create new attributes dict with filtered objectClasses
            new_attrs_dict = dict(entry.attributes.attributes)
            new_attrs_dict[FlextLdifConstants.DictKeys.OBJECTCLASS] = filtered_ocs

            new_attributes = FlextLdifModels.LdifAttributes(
                attributes=new_attrs_dict,
                metadata=entry.attributes.metadata,
            )

            # Create entry preserving metadata
            # DN is already validated by _validate_entry_dn() above
            # Use duck typing instead of isinstance to avoid class identity issues
            # between internal (FlextLdifModelsDomains) and public (FlextLdifModels) classes
            # Convert internal QuirkMetadata to public QuirkMetadata if needed
            metadata_public: FlextLdifModels.QuirkMetadata | None = None
            if entry.metadata is not None:
                metadata_public = FlextLdifModels.QuirkMetadata.model_validate(
                    entry.metadata.model_dump(),
                )
            # Convert internal DistinguishedName to public DistinguishedName if needed
            dn_public: str | FlextLdifModels.DistinguishedName
            if isinstance(entry.dn, FlextLdifModels.DistinguishedName):
                dn_public = entry.dn
            else:
                # Convert internal DN to public DN
                dn_public = FlextLdifModels.DistinguishedName.model_validate(
                    entry.dn.model_dump(),
                )
            entry_result = self._create_entry_with_metadata(
                dn=dn_public,
                attributes=new_attributes,
                metadata=metadata_public,
            )
            if entry_result.is_failure:
                error = entry_result.error or "Entry creation failed"
                return FlextResult.fail(error)

            return entry_result

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to remove objectClasses: {e}")


__all__ = ["FlextLdifEntryTransformer"]
