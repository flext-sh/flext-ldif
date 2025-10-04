"""FLEXT LDIF Results - Operation Result Models.

Result models for LDIF processing operations.
Extends flext-core FlextModels with LDIF-specific result entities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Self

from flext_core import FlextTypes
from pydantic import Field, computed_field, model_validator

# from flext_ldif.models import FlextLdifModels  # Temporarily removed to fix circular import


class FlextLdifResults:
    """Result models extending FlextModels.

    Contains result models for LDIF operations:
    - ParseResult: Parsing operation results
    - TransformResult: Transformation operation results
    - AnalyticsResult: Analytics operation results
    - WriteResult: Write operation results
    - FilterResult: Filter operation results
    """

    class ParseResult:
        """Parsing operation result with error tracking.

        Extends BaseOperationResult with parse-specific fields.
        """

        entries: list[dict] = Field(
            default_factory=list,
            description="Parsed entries",
        )
        line_count: int = Field(
            default=0,
            ge=0,
            description="Total lines parsed",
        )
        success_rate: float = Field(
            default=0.0,
            ge=0.0,
            le=100.0,
            description="Parse success rate percentage",
        )

        @computed_field
        def entry_count(self) -> int:
            """Get count of parsed entries."""
            return len(self.entries)

        @computed_field
        def is_success(self) -> bool:
            """Check if parsing was successful."""
            return len(self.errors) == 0 and len(self.entries) > 0

    class TransformResult:
        """Transformation operation result with change tracking.

        Extends BaseOperationResult with transformation-specific fields.
        """

        transformed_entries: list[dict] = Field(
            default_factory=list,
            description="Transformed entries",
        )
        transformation_log: FlextTypes.StringList = Field(
            default_factory=list,
            description="Log of transformations applied",
        )
        changes_count: int = Field(
            default=0,
            ge=0,
            description="Number of changes made",
        )

        @computed_field
        def entry_count(self) -> int:
            """Get count of transformed entries."""
            return len(self.transformed_entries)

    class AnalyticsResult:
        """Analytics operation result with pattern detection.

        Extends BaseOperationResult with analytics-specific fields.
        """

        total_entries: int = Field(
            default=0,
            description="Total number of entries analyzed",
        )
        statistics: dict[str, int | float] = Field(
            default_factory=dict,
            description="Statistical data",
        )
        patterns: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Detected patterns",
        )
        patterns_detected: FlextTypes.StringList = Field(
            default_factory=list,
            description="List of detected pattern names",
        )
        object_class_distribution: dict[str, int] = Field(
            default_factory=dict,
            description="Distribution of object classes",
        )
        dn_patterns: FlextTypes.StringList = Field(
            default_factory=list,
            description="Distinguished name patterns",
        )

        @computed_field
        def total_object_classes(self) -> int:
            """Get total unique object classes."""
            return len(self.object_class_distribution)

    class WriteResult:
        """Write operation result with success tracking.

        Extends BaseOperationResult with write-specific fields.
        """

        success: bool = Field(
            description="Whether write was successful",
        )
        file_path: str | None = Field(
            default=None,
            description="Path to written file",
        )
        entries_written: int = Field(
            default=0,
            ge=0,
            description="Number of entries written",
        )

        @model_validator(mode="after")
        def validate_write_consistency(self) -> Self:
            """Validate write result consistency."""
            if self.success and self.errors:
                msg = "success cannot be True when errors exist"
                raise ValueError(msg)
            if not self.success and self.entries_written > 0:
                msg = "entries_written should be 0 when success is False"
                raise ValueError(msg)
            return self

    class FilterResult:
        """Filter operation result with count tracking.

        Extends BaseOperationResult with filter-specific fields.
        """

        filtered_entries: list[dict] = Field(
            default_factory=list,
            description="Filtered entries",
        )
        original_count: int = Field(
            default=0,
            ge=0,
            description="Original entry count before filtering",
        )
        filtered_count: int = Field(
            default=0,
            ge=0,
            description="Count after filtering",
        )
        criteria: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Filter criteria used",
        )

        @model_validator(mode="after")
        def validate_filter_counts(self) -> Self:
            """Validate filter result counts."""
            if len(self.filtered_entries) != self.filtered_count:
                msg = "filtered_count does not match actual filtered entries"
                raise ValueError(msg)
            if self.filtered_count > self.original_count:
                msg = "filtered_count cannot exceed original_count"
                raise ValueError(msg)
            return self
