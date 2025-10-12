"""Quirk metadata domain model."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flext_core import FlextCore
from pydantic import Field


class QuirkMetadata(FlextCore.Models.Value):
    """Universal metadata container for quirk-specific data preservation.

    This model supports ANY quirk type and prevents data loss during RFC conversion.
    Quirks can store original format, timestamps, extensions, and custom data.

    Example:
        metadata = QuirkMetadata(
            original_format="( 2.16.840.1.113894... )",
            quirk_type="oud",
            extensions={"line_breaks": [45, 90], "dn_spaces": True}
        )

    """

    original_format: str | None = Field(
        default=None,
        description="Original string format before parsing (for perfect round-trip)",
    )
    quirk_type: str | None = Field(
        default=None,
        description="Quirk type that generated this metadata (oud, oid, openldap, etc.)",
    )
    parsed_timestamp: str | None = Field(
        default=None, description="Timestamp when data was parsed (ISO 8601 format)"
    )
    extensions: dict[str, Any] = Field(
        default_factory=dict,
        description="Quirk-specific extensions (line_breaks, dn_spaces, attribute_order, etc.)",
    )
    custom_data: dict[str, Any] = Field(
        default_factory=dict, description="Additional custom data for future quirks"
    )

    @classmethod
    def create_for_quirk(
        cls, quirk_type: str, original_format: str | None = None, **extensions: Any
    ) -> QuirkMetadata:
        """Factory method to create metadata for a specific quirk.

        Args:
            quirk_type: Type of quirk (oud, oid, openldap, etc.)
            original_format: Original string format
            **extensions: Quirk-specific extension data

        Returns:
            QuirkMetadata instance

        """
        return cls(
            quirk_type=quirk_type,
            original_format=original_format,
            parsed_timestamp=datetime.now(UTC).isoformat(),
            extensions=extensions,
        )
