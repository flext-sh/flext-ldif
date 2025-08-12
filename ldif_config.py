"""FLEXT-LDIF Configuration - Enterprise LDIF Processing Configuration.

CONSOLIDATED PEP8 ARCHITECTURE: This module consolidates LDIF configuration
into ONE centralized, PEP8-compliant configuration module.

CONSOLIDATION MAPPING:
✅ src/flext_ldif/config.py → Complete LDIF configuration management

Enterprise Configuration Features:
- RFC 2849 LDIF format compliance
- Environment variable integration
- Type-safe configuration with Pydantic
- Business rule validation
- File processing settings
- Entry processing limits

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextConfig
from flext_core.result import FlextResult
from pydantic import Field

# RFC 2849 constants for line wrap lengths
MIN_LINE_WRAP_LENGTH: int = 50
MAX_LINE_WRAP_LENGTH: int = 998


class FlextLdifConfig(FlextConfig):
    """LDIF processing configuration using flext-core FlextConfig foundation.

    ✅ CORRECT ARCHITECTURE: Extends FlextConfig from flext-core.
    ZERO duplication - uses existing flext-core configuration patterns.

    Configuration covers all aspects of LDIF processing:
    - File I/O settings with encoding management
    - Processing limits and performance tuning
    - LDIF format compliance (RFC 2849)
    - Validation strictness levels
    - Output formatting options
    """

    # Processing settings
    max_entries: int = Field(default=20000, description="Maximum number of entries to process")
    max_entry_size: int = Field(default=1048576, description="Maximum size per entry in bytes (1MB)")
    strict_validation: bool = Field(default=True, description="Enable strict LDIF validation")

    # File settings
    input_encoding: str = Field(default="utf-8", description="Input file encoding")
    output_encoding: str = Field(default="utf-8", description="Output file encoding")
    output_directory: Path = Field(default_factory=Path.cwd, description="Output directory for generated files")
    create_output_dir: bool = Field(default=True, description="Create output directory if it doesn't exist")

    # LDIF format settings (RFC 2849 compliance)
    line_wrap_length: int = Field(default=76, description="LDIF line wrap length (RFC 2849)")
    sort_attributes: bool = Field(default=False, description="Sort attributes in output")
    normalize_dn: bool = Field(default=False, description="Normalize DN values")
    allow_empty_attributes: bool = Field(default=False, description="Allow empty attribute values")

    # Buffer and performance settings
    file_buffer_size: int = Field(default=8192, description="File I/O buffer size in bytes")
    max_file_size_mb: int = Field(default=100, description="Maximum input file size in MB")

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDIF configuration business rules with detailed errors."""
        # RFC 2849 compliance - line wrap length must be within valid range
        if not (MIN_LINE_WRAP_LENGTH <= self.line_wrap_length <= MAX_LINE_WRAP_LENGTH):
            return FlextResult.fail(
                f"line_wrap_length must be between {MIN_LINE_WRAP_LENGTH} and {MAX_LINE_WRAP_LENGTH}",
            )

        # Encoding validation - ensure encodings are valid
        try:
            "test".encode(self.input_encoding)
            "test".encode(self.output_encoding)
        except LookupError:
            return FlextResult.fail("Invalid input or output encoding specified")

        # Entry size validation
        if self.max_entry_size <= 0:
            return FlextResult.fail("max_entry_size must be positive")

        # Entry count validation
        if self.max_entries <= 0:
            return FlextResult.fail("max_entries must be positive")

        # File size validation
        if self.max_file_size_mb <= 0:
            return FlextResult.fail("max_file_size_mb must be positive")

        # Buffer size validation
        if self.file_buffer_size <= 0:
            return FlextResult.fail("file_buffer_size must be positive")

        return FlextResult.ok(None)


__all__ = ["MAX_LINE_WRAP_LENGTH", "MIN_LINE_WRAP_LENGTH", "FlextLdifConfig"]
