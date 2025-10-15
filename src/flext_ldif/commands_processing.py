"""Processing CQRS commands and queries."""

from flext_core import FlextCore
from pydantic import Field


class ParseQuery(FlextCore.Models.Query):
    """Query for parsing LDIF content."""

    source: str = Field(
        ..., min_length=1, description="LDIF source content, file path, or lines"
    )
    format: str = Field(default="auto", description="LDIF format to use for parsing")
    encoding: str = Field(
        default="utf-8", description="Character encoding for LDIF content"
    )
    strict: bool = Field(
        default=True, description="Whether to use strict validation during parsing"
    )


class ValidateQuery(FlextCore.Models.Query):
    """Query for validating LDIF entries."""

    entries: FlextCore.Types.List = Field(..., description="Entries to validate")
    schema_config: FlextCore.Types.Dict | None = Field(
        default=None, description="Schema configuration for validation"
    )
    strict: bool = Field(default=True, description="Whether to use strict validation")


class AnalyzeQuery(FlextCore.Models.Query):
    """Query for analyzing LDIF entries."""

    ldif_content: str = Field(..., description="LDIF content to analyze")
    analysis_types: FlextCore.Types.StringList = Field(
        ..., description="Types of analysis to perform"
    )
    metrics: FlextCore.Types.Dict | None = Field(
        default=None, description="Metrics configuration"
    )
    include_patterns: bool = Field(
        default=True, description="Whether to include pattern detection"
    )


class WriteCommand(FlextCore.Models.Command):
    """Command for writing entries to LDIF format."""

    entries: FlextCore.Types.List = Field(..., description="Entries to write")
    format: str = Field(default="rfc", description="Output LDIF format")
    output: str | None = Field(
        default=None, description="Output path (None for string return)"
    )
    line_width: int = Field(default=76, ge=40, le=120, description="Maximum line width")


class MigrateCommand(FlextCore.Models.Command):
    """Command for migrating LDIF entries between server types."""

    entries: FlextCore.Types.List = Field(..., description="Entries to migrate")
    source_format: str = Field(..., description="Source LDIF format")
    target_format: str = Field(..., description="Target LDIF format")
    options: FlextCore.Types.Dict | None = Field(
        default=None, description="Migration options"
    )


class RegisterQuirkCommand(FlextCore.Models.Command):
    """Command for registering server-specific quirks."""

    quirk_type: str = Field(..., description="Type of quirk to register")
    quirk_impl: object = Field(..., description="Quirk implementation instance")
    override: bool = Field(
        default=False, description="Whether to override existing quirk"
    )
