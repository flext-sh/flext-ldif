"""FLEXT-LDIF Configuration."""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextConfig
from flext_core.result import FlextResult
from pydantic import Field

# RFC 2849 constants for line wrap lengths
MIN_LINE_WRAP_LENGTH: int = 50
MAX_LINE_WRAP_LENGTH: int = 998


class FlextLdifConfig(FlextConfig):
    """LDIF processing configuration."""

    max_entries: int = Field(default=20000)
    max_entry_size: int = Field(default=1048576)
    strict_validation: bool = Field(default=True)
    input_encoding: str = Field(default="utf-8")
    output_encoding: str = Field(default="utf-8")
    output_directory: Path = Field(default_factory=Path.cwd)
    create_output_dir: bool = Field(default=True)
    line_wrap_length: int = Field(default=76)
    sort_attributes: bool = Field(default=False)
    normalize_dn: bool = Field(default=False)
    allow_empty_attributes: bool = Field(default=False)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDIF configuration business rules."""
        if not (MIN_LINE_WRAP_LENGTH <= self.line_wrap_length <= MAX_LINE_WRAP_LENGTH):
            return FlextResult.fail(
                f"line_wrap_length must be between {MIN_LINE_WRAP_LENGTH} and {MAX_LINE_WRAP_LENGTH}",
            )

        try:
            "test".encode(self.input_encoding)
            "test".encode(self.output_encoding)
        except LookupError:
            from .constants import FlextLdifValidationMessages
            return FlextResult.fail(FlextLdifValidationMessages.INVALID_ENCODING)

        return FlextResult.ok(None)


__all__ = ["FlextLdifConfig"]
