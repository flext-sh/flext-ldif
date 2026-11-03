# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/domain_entry
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence, Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_cli import p

    from flext_ldif import t
    from flext_ldif._constants import FlextLdifConstantsBaseParts
    from flext_ldif._protocols import (
        FlextLdifProtocolsDomainAttributes,
        FlextLdifProtocolsDomainDn,
        FlextLdifProtocolsDomainEntryChange,
        FlextLdifProtocolsDomainEntryControl,
        FlextLdifProtocolsDomainMetadata,
    )
    from flext_ldif._typings import FlextLdifTypesBase


class FlextLdifProtocolsDomainEntry:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class Entry(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def domain_events(self) -> Sequence[p.DomainEvent]:
            """List of uncommitted domain events for event sourcing."""
            ...

        @property
        def dn(self) -> FlextLdifProtocolsDomainDn.DN | None:
            """Structural member projected from the owning model.

            Distinguished Name of the entry (REQUIRED per RFC 2849 § 2). Allows None
            for RFC violation capture. Coerced from str via m.field_validator -
            PROTOCOL COMPATIBLE with p.Ldif.Entry.Entry.
            """
            ...

        @property
        def attributes(self) -> FlextLdifProtocolsDomainAttributes.Attributes | None:
            """Structural member projected from the owning model.

            Entry attributes container (REQUIRED per RFC 2849 § 2). Allows None for
            RFC violation capture. Coerced from dict[str, list[str]] via
            m.field_validator - PROTOCOL COMPATIBLE with p.Ldif.Entry.Entry.
            """
            ...

        @property
        def record_kind(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.RecordKind:
            """Structural member projected from the owning model.

            Whether this Entry represents LDIF content or an LDIF change record.
            """
            ...

        @property
        def controls(self) -> Sequence[FlextLdifProtocolsDomainEntryControl.Control]:
            """RFC 2849 control lines associated with the record."""
            ...

        @property
        def change_operations(
            self,
        ) -> Sequence[FlextLdifProtocolsDomainEntryChange.ChangeOperation]:
            """Structured modify operation blocks for changetype=modify."""
            ...

        @property
        def changetype(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ChangeType | None:
            """Structural member projected from the owning model.

            Change operation type per RFC 2849 § 5.7
            (add/delete/modify/moddn/modrdn).
            """
            ...

        newrdn: str | None
        deleteoldrdn: bool | None
        newsuperior: str | None
        raw_record_lines: MutableSequence[str]

        @property
        def metadata(self) -> FlextLdifProtocolsDomainMetadata.ServerMetadata | None:
            """Structural member projected from the owning model.

            Server-specific metadata for processing data, ACLs, statistics,
            validation (non-RFC data).
            """
            ...

        @property
        def validation_metadata(self) -> p.ConfigMap | None:
            """Validation metadata captured during parsing and transformation."""
            ...

        @property
        def attributes_dict(self) -> t.MutableStrSequenceMapping:
            """Attribute mapping required by the entry protocol."""
            ...

        @property
        def dn_str(self) -> str:
            """String form of the DN required by the entry protocol."""
            ...

        @property
        def is_change_record(self) -> bool:
            """True when the entry represents an LDIF change record."""
            ...

        @property
        def unconverted_attributes(self) -> FlextLdifTypesBase.UnconvertedAttributes:
            """Raw attributes preserved from parsing, before conversion."""
            ...

        @property
        def has_validation_errors(self) -> bool:
            """Presence of validation errors in the validation metadata."""
            ...

        @property
        def is_acl_entry(self) -> bool:
            """Presence of Access Control Lists on the entry."""
            ...

        @property
        def is_schema_entry(self) -> bool:
            """Schema-definition status of the entry."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsDomainEntry",
]
