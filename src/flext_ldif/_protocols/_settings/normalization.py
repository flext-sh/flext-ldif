# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/_settings/normalization
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_cli import FlextCliProtocols


class FlextLdifProtocolsSettingsNormalization:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class DnNormalizationConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def case_sensitive(self) -> bool:
            """Whether DN comparison is case-sensitive."""
            ...

        @property
        def remove_spaces(self) -> bool:
            """Remove spaces around DN component separators."""
            ...

        @property
        def case_fold(self) -> str | None:
            """Case folding strategy for DN comparison."""
            ...

        @property
        def space_handling(self) -> str | None:
            """Strategy for handling spaces in DN values."""
            ...

        @property
        def escape_handling(self) -> str | None:
            """Strategy for handling escape sequences in DN."""
            ...

        @property
        def validate_before(self) -> bool:
            """Validate DN format before normalization."""
            ...

    @runtime_checkable
    class AttrNormalizationConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def lowercase_keys(self) -> bool:
            """Convert attribute names to lowercase."""
            ...

        @property
        def sort_values(self) -> bool:
            """Sort attribute values alphabetically."""
            ...

        @property
        def sort_attributes(self) -> str | None:
            """Attribute sorting strategy."""
            ...

        @property
        def normalize_whitespace(self) -> bool:
            """Normalize whitespace in attribute values."""
            ...

        @property
        def case_fold_names(self) -> bool:
            """Case-fold attribute names for comparison."""
            ...

        @property
        def trim_values(self) -> bool:
            """Trim leading and trailing whitespace from values."""
            ...

        @property
        def remove_empty(self) -> bool:
            """Remove attributes with empty values."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsSettingsNormalization",
]
