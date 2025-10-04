"""FLEXT LDIF Commands - CQRS Commands and Queries.

Domain commands and queries for LDIF processing operations.
Extends flext-core FlextModels with LDIF-specific CQRS patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from flext_core import FlextModels, FlextTypes
from pydantic import ConfigDict, Field

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifModels


class FlextLdifCommands:
    """LDIF-specific CQRS commands and queries extending FlextModels.

    Contains all command and query objects for LDIF processing operations,
    following CQRS patterns with immutable queries and mutable commands.
    """

    class ParseQuery(FlextModels.Query):
        """Query to parse LDIF content from various sources.

        Immutable query object following CQRS pattern for read-only operations.
        """

        source: str | bytes | FlextTypes.StringList = Field(
            ..., description="LDIF source content, file path, or lines"
        )
        format: Literal["rfc", "oid", "auto"] = Field(
            default="auto", description="LDIF format to use for parsing"
        )
        encoding: str = Field(default="utf-8", description="Text encoding")
        strict: bool = Field(default=True, description="Strict RFC compliance")

        model_config = ConfigDict(frozen=True)

    class ValidateQuery(FlextModels.Query):
        """Query to validate LDIF entries against schema.

        Immutable query object for validation operations without side effects.
        """

        entries: list[FlextLdifModels.Entry] = Field(
            ..., description="Entries to validate"
        )
        schema_config: FlextTypes.Dict | None = Field(
            default=None, description="Schema configuration"
        )
        strict: bool = Field(default=True, description="Strict validation mode")

        # Legacy compatibility alias
        @property
        def schema_validation(self) -> bool:
            """Legacy alias for strict validation mode."""
            return self.strict

        model_config = ConfigDict(frozen=True)

    class AnalyzeQuery(FlextModels.Query):
        """Query to analyze LDIF entries and generate statistics.

        Immutable query object for analytics operations.
        """

        entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list, description="Entries to analyze"
        )
        metrics: FlextTypes.StringList | None = Field(
            default=None, description="Specific metrics to calculate"
        )
        include_patterns: bool = Field(
            default=True, description="Include pattern detection"
        )

        # Legacy compatibility fields
        ldif_content: str | None = Field(
            default=None, description="Legacy LDIF content field"
        )
        analysis_types: FlextTypes.StringList | None = Field(
            default=None, description="Legacy analysis types field"
        )

        model_config = ConfigDict(frozen=True, extra="allow")

    class WriteCommand(FlextModels.Command):
        """Command to write LDIF entries to output.

        Command object for write operations with side effects.
        """

        entries: list[FlextLdifModels.Entry] = Field(
            ..., description="Entries to write"
        )
        format: Literal["rfc", "oid"] = Field(
            default="rfc", description="Output LDIF format"
        )
        output: str | None = Field(default=None, description="Output file path")
        line_width: int = Field(
            default=76, description="Maximum line width for wrapping", ge=40, le=200
        )

        # Legacy compatibility fields
        output_path: str | None = Field(
            default=None, description="Legacy output path field"
        )
        format_options: FlextTypes.Dict = Field(
            default_factory=dict, description="Legacy format options field"
        )

    class MigrateCommand(FlextModels.Command):
        """Command to migrate LDIF entries between formats.

        Command object for migration operations with transformations.
        """

        entries: list[FlextLdifModels.Entry] = Field(
            ..., description="Entries to migrate"
        )
        source_format: Literal["rfc", "oid", "oud"] = Field(
            ..., description="Source LDIF format"
        )
        target_format: Literal["rfc", "oid", "oud"] = Field(
            ..., description="Target LDIF format"
        )
        quirks: FlextTypes.StringList | None = Field(
            default=None, description="Quirks to apply during migration"
        )
        preserve_comments: bool = Field(
            default=True, description="Preserve comments during migration"
        )

    class RegisterQuirkCommand(FlextModels.Command):
        """Command to register a custom quirk.

        Command object for registry modification operations.
        """

        quirk_type: Literal["schema", "acl", "entry"] = Field(
            ..., description="Type of quirk to register"
        )
        quirk_impl: object = Field(..., description="Quirk implementation")
        override: bool = Field(
            default=False, description="Override existing quirk if present"
        )
