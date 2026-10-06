"""Entry statistics model for LDIF entry lifecycle tracking.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, Self

from flext_core import FlextUtilities as u, m
from flext_ldif import t
from flext_ldif._models.domain_dn import FlextLdifModelsDomainDN as mdn
from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif


class FlextLdifModelsDomainEntryStatistics(m.FrozenDynamicModel):
    """Statistics tracking for entry-level transformations and validation.

    Tracks complete entry lifecycle from parsing through validation,
    transformation, filtering, and output. Captures all attribute
    modifications, server applications, and rejection reasons.

    Designed for aggregation across large LDIF files to provide
    comprehensive migration diagnostics.

    Inherits from m.BaseModel (flext-core):
    - model_config (frozen=True, validate_default=True, validate_assignment=True)
    - aggregate() classmethod (automatic statistics aggregation)
    """

    was_parsed: Annotated[
        bool,
        u.Field(description="Entry was successfully parsed from LDIF"),
    ] = True
    was_validated: Annotated[
        bool,
        u.Field(description="Entry passed validation checks"),
    ] = False
    was_filtered: Annotated[
        bool,
        u.Field(description="Entry was filtered by rules (base DN, schema, etc.)"),
    ] = False
    was_written: Annotated[
        bool,
        u.Field(description="Entry was written to output LDIF"),
    ] = False
    was_rejected: Annotated[
        bool,
        u.Field(description="Entry was rejected during processing"),
    ] = False
    rejection_category: Annotated[
        str | None,
        u.Field(description="Rejection category (use RejectionCategory constants)"),
    ] = None
    rejection_reason: Annotated[
        str | None,
        u.Field(description="Human-readable rejection reason"),
    ] = None
    attributes_added: Annotated[
        t.MutableSequenceOf[str],
        u.Field(description="Attribute names added during processing"),
    ]
    attributes_removed: Annotated[
        t.MutableSequenceOf[str],
        u.Field(description="Attribute names removed during processing"),
    ]
    attributes_modified: Annotated[
        t.MutableSequenceOf[str],
        u.Field(description="Attribute names modified during processing"),
    ]
    attributes_filtered: Annotated[
        t.MutableSequenceOf[str],
        u.Field(description="Attribute names filtered by whitelist/blacklist"),
    ]
    objectclasses_original: Annotated[
        t.MutableSequenceOf[str],
        u.Field(description="Original objectClass values"),
    ]
    objectclasses_final: Annotated[
        t.MutableSequenceOf[str],
        u.Field(description="Final objectClass values after transformation"),
    ]
    servers_applied: Annotated[
        t.MutableSequenceOf[str],
        u.Field(description="List of server types applied to this entry"),
    ]
    server_transformations: Annotated[
        int,
        u.Field(description="Count of server transformations applied"),
    ] = 0
    dn_statistics: Annotated[
        mdn.DNStatistics | None,
        u.Field(description="DN transformation statistics (if applicable)"),
    ] = None
    filters_applied: Annotated[
        t.MutableSequenceOf[str],
        u.Field(description="List of filters applied (use FilterType constants)"),
    ]
    filter_results: Annotated[
        t.MutableBoolMapping,
        u.Field(description="Filter results: {filter_name: passed}"),
    ]
    errors: Annotated[
        t.MutableSequenceOf[str],
        u.Field(
            description="Error messages (use ErrorCategory constants for keys)",
        ),
    ]
    warnings: Annotated[
        t.MutableSequenceOf[str],
        u.Field(description="Warning messages"),
    ]
    category_assigned: Annotated[
        str | None,
        u.Field(
            description="Category assigned (schema, hierarchy, users, groups, acl)",
        ),
    ] = None
    category_confidence: Annotated[
        float,
        u.Field(
            ge=0.0,
            le=1.0,
            description="Confidence score for category assignment",
        ),
    ] = 1.0

    @u.computed_field
    @property
    def dn_was_transformed(self) -> bool:
        """Whether DN underwent transformation."""
        if self.dn_statistics is None:
            return False
        return self.dn_statistics.was_transformed

    @u.computed_field
    @property
    def had_errors(self) -> bool:
        """Whether any errors occurred."""
        return bool(self.errors)

    @u.computed_field
    @property
    def had_warnings(self) -> bool:
        """Whether any warnings occurred."""
        return bool(self.warnings)

    @u.computed_field
    @property
    def objectclasses_changed(self) -> bool:
        """Whether objectClass values changed."""
        return set(self.objectclasses_original) != set(self.objectclasses_final)

    @u.computed_field
    @property
    def total_attribute_changes(self) -> int:
        """Total count of attribute modifications."""
        return (
            len(self.attributes_added)
            + len(self.attributes_removed)
            + len(self.attributes_modified)
        )

    @classmethod
    def create_minimal(cls) -> Self:
        """Create minimal statistics for newly parsed entry.

        Returns:
            The resulting ``Self``.
        """
        validated: Self = cls.model_validate({"was_parsed": True})
        return validated

    @u.field_validator("filters_applied", mode="after")
    @classmethod
    def deduplicate_filters(
        cls,
        v: t.MutableSequenceOf[str],
    ) -> t.MutableSequenceOf[str]:
        """Remove duplicate filters while preserving order.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        seen: set[str] = set()
        result: t.MutableSequenceOf[str] = []
        for item in v:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result

    @u.field_validator("servers_applied", mode="after")
    @classmethod
    def deduplicate_servers(
        cls,
        v: t.MutableSequenceOf[str],
    ) -> t.MutableSequenceOf[str]:
        """Remove duplicate servers while preserving order.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        return FlextLdifUtilitiesCollectionLdif.deduplicate_preserve_order(v)

    def add_error(self, error: str) -> Self:
        """Add error message.

        Returns new instance with error added (frozen model).

        Returns:
            The resulting ``Self``.
        """
        errors = [*self.errors, error]
        copy_result: Self = self.model_copy(update={"errors": errors})
        return copy_result

    def add_warning(self, warning: str) -> Self:
        """Add warning message.

        Returns new instance with warning added (frozen model).

        Returns:
            The resulting ``Self``.
        """
        warnings = [*self.warnings, warning]
        copy_result: Self = self.model_copy(update={"warnings": warnings})
        return copy_result

    def mark_filtered(self, filter_type: str, *, passed: bool) -> Self:
        """Mark entry as filtered with result.

        Args:
            filter_type: Type of filter applied
            passed: Whether entry passed the filter (keyword-only)

        Returns new instance with updated filter state (frozen model).

        Returns:
            The resulting ``Self``.
        """
        filters_applied = [*self.filters_applied, filter_type]
        filter_results = {**self.filter_results, filter_type: passed}
        copy_result: Self = self.model_copy(
            update={
                "was_filtered": True,
                "filters_applied": filters_applied,
                "filter_results": filter_results,
            },
        )
        return copy_result

    def mark_rejected(self, category: str, reason: str) -> Self:
        """Mark entry as rejected.

        Returns new instance with rejection details (frozen model).

        Returns:
            The resulting ``Self``.
        """
        copy_result: Self = self.model_copy(
            update={
                "was_rejected": True,
                "rejection_category": category,
                "rejection_reason": reason,
            },
        )
        return copy_result

__all__: list[str] = ["FlextLdifModelsDomainEntryStatistics"]
