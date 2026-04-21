"""DN domain models — Distinguished Name, statistics, and registry.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import (
    MutableMapping,
    MutableSequence,
)
from typing import Annotated, ClassVar, Self, override

from flext_cli import m, u

from flext_ldif import FlextLdifModelsMetadata as mdm, c, r, t


class FlextLdifModelsDomainDN:
    """Namespace for DN-related domain models."""

    class DNStatistics(m.FrozenDynamicModel):
        """Statistics tracking for DN transformations and validation."""

        original_dn: Annotated[
            str,
            u.Field(..., description="Original DN as received from input"),
        ]
        cleaned_dn: Annotated[
            str,
            u.Field(..., description="DN after clean_dn() transformation"),
        ]
        normalized_dn: Annotated[
            str,
            u.Field(..., description="Final normalized DN (RFC 4514 compliant)"),
        ]
        transformations: Annotated[
            t.StrSequence,
            u.Field(description="Ordered list of transformations applied"),
        ]
        had_tab_chars: Annotated[
            bool,
            u.Field(description="DN contained TAB characters"),
        ] = False
        had_trailing_spaces: Annotated[
            bool,
            u.Field(description="DN had trailing spaces"),
        ] = False
        had_leading_spaces: Annotated[
            bool,
            u.Field(description="DN had leading spaces"),
        ] = False
        had_extra_spaces: Annotated[
            bool,
            u.Field(description="DN had multiple consecutive spaces"),
        ] = False
        was_base64_encoded: Annotated[
            bool,
            u.Field(description="DN was base64 encoded in LDIF (dn::)"),
        ] = False
        had_utf8_chars: Annotated[
            bool,
            u.Field(description="DN contained UTF-8 multi-byte characters"),
        ] = False
        had_escape_sequences: Annotated[
            bool,
            u.Field(description="DN contained LDAP escape sequences"),
        ] = False
        validation_status: Annotated[
            str,
            u.Field(
                description="Validation status (use ValidationStatus constants)",
            ),
        ] = "valid"
        validation_warnings: Annotated[
            t.StrSequence,
            u.Field(description="Non-fatal validation warnings"),
        ]
        validation_errors: Annotated[
            t.StrSequence,
            u.Field(description="Fatal validation errors"),
        ]

        @u.computed_field()
        @property
        def has_errors(self) -> bool:
            """Check if any validation errors exist."""
            return bool(self.validation_errors)

        @u.computed_field()
        @property
        def has_warnings(self) -> bool:
            """Check if any validation warnings exist."""
            return bool(self.validation_warnings)

        @u.computed_field()
        @property
        def transformation_count(self) -> int:
            """Count of unique transformations applied."""
            return len(self.transformations)

        @u.computed_field()
        @property
        def was_transformed(self) -> bool:
            """Check if any transformations were applied."""
            return self.original_dn != self.normalized_dn or bool(
                self.transformations,
            )

        @classmethod
        def create_minimal(cls, dn: str) -> Self:
            """Create minimal statistics for unchanged DN."""
            return cls.model_validate({
                "original_dn": dn,
                "cleaned_dn": dn,
                "normalized_dn": dn,
            })

        @u.field_validator("transformations", mode="after")
        @classmethod
        def deduplicate_transformations(
            cls,
            v: MutableSequence[str],
        ) -> MutableSequence[str]:
            """Remove duplicate transformations while preserving order."""
            seen: set[str] = set()
            result: MutableSequence[str] = []
            for item in v:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            return result

    class DNStatisticsFlags(m.FrozenModel):
        """Flags capturing DN transformation quirks and validation state."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(frozen=True)
        had_tab_chars: Annotated[
            bool,
            u.Field(description="DN contained TAB characters"),
        ] = False
        had_trailing_spaces: Annotated[
            bool,
            u.Field(description="DN had trailing spaces"),
        ] = False
        had_leading_spaces: Annotated[
            bool,
            u.Field(description="DN had leading spaces"),
        ] = False
        had_extra_spaces: Annotated[
            bool,
            u.Field(description="DN had multiple consecutive spaces"),
        ] = False
        was_base64_encoded: Annotated[
            bool,
            u.Field(description="DN was base64 encoded in LDIF (dn::)"),
        ] = False
        had_utf8_chars: Annotated[
            bool,
            u.Field(description="DN contained UTF-8 multi-byte characters"),
        ] = False
        had_escape_sequences: Annotated[
            bool,
            u.Field(description="DN contained LDAP escape sequences"),
        ] = False
        validation_status: Annotated[
            str,
            u.Field(
                description="Validation status (use ValidationStatus constants)",
            ),
        ] = "valid"
        validation_warnings: Annotated[
            MutableSequence[str],
            u.Field(description="Non-fatal validation warnings"),
        ] = u.Field(default_factory=list)
        validation_errors: Annotated[
            MutableSequence[str],
            u.Field(description="Fatal validation errors"),
        ] = u.Field(default_factory=list)

    class DN(m.Value):
        """Distinguished Name value."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            strict=True,
            frozen=True,
            extra="forbid",
            validate_default=True,
            use_enum_values=True,
            str_strip_whitespace=True,
        )
        value: Annotated[
            str,
            u.Field(
                ...,
                description="DN string value (lenient processing - no max_length)",
            ),
        ]
        metadata: Annotated[
            mdm.EntryMetadata,
            u.Field(
                description="Quirk-specific metadata for preserving original format",
            ),
        ] = u.Field(default_factory=mdm.EntryMetadata)
        _DN_COMPONENT_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            c.Ldif.DN_COMPONENT,
            re.IGNORECASE,
        )

        @override
        def __str__(self) -> str:
            """Return DN value as string for str() conversion."""
            return self.value

        @classmethod
        def from_value(cls, dn: str | Self | None) -> Self:
            """Create DN from string or existing instance."""
            if dn is None:
                msg = "dn cannot be None"
                raise ValueError(msg)
            return cls.model_validate({
                "value": str(dn),
                "metadata": mdm.EntryMetadata.model_validate(
                    {},
                ),
            })

    class DnRegistry(m.StrictModel):
        """Registry for tracking canonical DN case during conversions."""

        def __init__(self) -> None:
            """Initialize empty DN case registry."""
            super().__init__()
            self._registry: mdm.DynamicMetadata = mdm.DynamicMetadata()
            self._case_variants: MutableMapping[str, set[str]] = {}

        @staticmethod
        def _normalize_dn(dn: str) -> str:
            """Convert DN to lowercase for case-insensitive dict lookup."""
            return dn.lower().replace(" ", "")

        def clear(self) -> None:
            """Clear all DN registrations."""
            self._registry.clear()
            self._case_variants.clear()

        def get_canonical_dn(self, dn: str) -> str | None:
            """Get canonical case for a DN (case-insensitive lookup)."""
            normalized = self._normalize_dn(dn)
            value = self._registry.get(normalized)
            if isinstance(value, str):
                return value
            return None

        def register_dn(self, dn: str, *, force: bool = False) -> str:
            """Register DN and return its canonical case."""
            normalized = self._normalize_dn(dn)
            if normalized not in self._case_variants:
                self._case_variants[normalized] = set[str]()
            self._case_variants[normalized].add(dn)
            if normalized not in self._registry or force:
                self._registry[normalized] = dn
            value = self._registry[normalized]
            return str(value)

        def validate_oud_consistency(self) -> r[bool]:
            """Validate DN case consistency for server conversion."""
            inconsistencies: MutableSequence[
                MutableMapping[str, str | int | MutableSequence[str]]
            ] = []
            for normalized_dn, variants in self._case_variants.items():
                if len(variants) > 1:
                    canonical_value = self._registry.get(normalized_dn)
                    canonical = (
                        canonical_value if isinstance(canonical_value, str) else ""
                    )
                    inconsistencies.append({
                        "normalized_dn": normalized_dn,
                        "canonical_case": canonical,
                        "variants": list(variants),
                        "variant_count": len(variants),
                    })
            if inconsistencies:
                return r[bool].ok(False)
            return r[bool].ok(True)


__all__: list[str] = ["FlextLdifModelsDomainDN"]
