# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/_settings/criteria
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence, Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import c, t


class FlextLdifProtocolsSettingsCriteria:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class ServerPatternsConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def oid_pattern(self) -> str:
            """Regex pattern used for schema OID detection."""
            ...

        @property
        def dn_patterns(self) -> tuple[Sequence[str], ...]:
            """Structural member projected from the owning model.

            Tuple of DN pattern tuples - entry matches if ALL patterns in ANY tuple
            match.
            """
            ...

        @property
        def attr_prefixes(self) -> Sequence[str] | frozenset[str]:
            """Attribute name prefixes to check."""
            ...

        @property
        def attr_names(self) -> frozenset[str] | set[str]:
            """Set of attribute names that indicate this server."""
            ...

        @property
        def keyword_patterns(self) -> Sequence[str]:
            """Keywords to search in attribute names."""
            ...

        @property
        def detection_string(self) -> str | None:
            """Optional substring used for server name matching."""
            ...

        @property
        def name_regex(self) -> str | None:
            """Optional regex used to extract schema names from raw definitions."""
            ...

        @property
        def use_prefix_match(self) -> bool:
            """Whether detection names match by prefix instead of exact value."""
            ...

        @property
        def match_definition_text(self) -> bool:
            """Structural member projected from the owning model.

            Whether raw definition text should be scanned for detection markers.
            """
            ...

    @runtime_checkable
    class EntryDetectionMarkers(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def dn_markers(self) -> frozenset[str]:
            """Substrings that identify the dialect DN."""
            ...

        @property
        def objectclass_names(self) -> frozenset[str]:
            """ObjectClass names of the dialect."""
            ...

        @property
        def attribute_names(self) -> frozenset[str]:
            """Attribute names that identify the dialect."""
            ...

        @property
        def attribute_prefixes(self) -> frozenset[str]:
            """Attribute-name prefixes of the dialect."""
            ...

    @runtime_checkable
    class EntryCriteriaConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def objectclasses(self) -> MutableSequence[str] | None:
            """Required objectClasses."""
            ...

        @property
        def objectclass_mode(self) -> c.Ldif.EntryCriteriaMode:
            """Match mode: "any" (has any) or "all" (has all)."""
            ...

        @property
        def required_attrs(self) -> MutableSequence[str] | None:
            """All of these attributes must exist."""
            ...

        @property
        def any_attrs(self) -> MutableSequence[str] | None:
            """At least one of these attributes must exist."""
            ...

        @property
        def dn_pattern(self) -> str | None:
            """Regex pattern that DN must match."""
            ...

        @property
        def is_schema(self) -> bool | None:
            """If set, entry must (True) or must not (False) be schema."""
            ...

    @runtime_checkable
    class EntryParseMetadataConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def server_type(self) -> c.Ldif.ServerTypes:
            """Server type performing the parse (oid, oud, rfc, etc.)."""
            ...

        @property
        def original_entry_dn(self) -> str:
            """Original DN as parsed from LDIF."""
            ...

        @property
        def cleaned_dn(self) -> str:
            """Cleaned/normalized DN."""
            ...

        @property
        def original_dn_line(self) -> str | None:
            """Original DN line from LDIF (with folding if present)."""
            ...

        @property
        def original_attr_lines(self) -> MutableSequence[str] | None:
            """Original attribute lines from LDIF."""
            ...

        @property
        def dn_was_base64(self) -> bool:
            """Whether DN was base64 encoded."""
            ...

        @property
        def original_attribute_case(self) -> t.MutableStrMapping | None:
            """Mapping of attribute names to original case."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsSettingsCriteria",
]
