"""FLEXT-LDIF Configuration - Unified Semantic Pattern Integration.

⚡ ZERO BOILERPLATE: Using flext-core configuration patterns.

Eliminates custom configuration boilerplate by extending FlextConfig foundation.

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextResult
from pydantic import BaseModel, Field

# RFC 2849 constants for line wrap lengths
MIN_LINE_WRAP_LENGTH: int = 50
MAX_LINE_WRAP_LENGTH: int = 998


class FlextLdifConfig(BaseModel):
    """LDIF processing configuration using unified patterns."""

    # Processing settings
    max_entries: int = Field(default=10000, ge=1, le=1000000)
    max_entry_size: int = Field(default=1048576, ge=1024, le=104857600)
    strict_validation: bool = Field(default=True)

    # File settings
    input_encoding: str = Field(default="utf-8")
    output_encoding: str = Field(default="utf-8")
    output_directory: Path = Field(default_factory=Path.cwd)
    create_output_dir: bool = Field(default=True)

    # LDIF format settings
    line_wrap_length: int = Field(default=76, ge=50, le=998)
    sort_attributes: bool = Field(default=False)
    normalize_dn: bool = Field(default=False)
    allow_empty_attributes: bool = Field(default=False)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDIF configuration business rules."""
        # RFC 2849 compliance
        if not (MIN_LINE_WRAP_LENGTH <= self.line_wrap_length <= MAX_LINE_WRAP_LENGTH):
            return FlextResult.fail(
                f"Line wrap length {self.line_wrap_length} violates RFC 2849",
            )

        # Encoding validation
        try:
            "test".encode(self.input_encoding)
            "test".encode(self.output_encoding)
        except LookupError as e:
            return FlextResult.fail(f"Invalid encoding: {e}")

        return FlextResult.ok(None)


__all__ = ["FlextLdifConfig"]
