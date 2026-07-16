"""Protocol-based LDIF composite type aliases."""

from __future__ import annotations

from flext_cli import t
from flext_ldif._protocols.base import FlextLdifProtocolsBase
from flext_ldif._protocols.domain import FlextLdifProtocolsDomain


class FlextLdifTypesDomain:
    """Composite LDIF aliases built from canonical protocols."""

    # NOTE (multi-agent, mro-0ftd.3.7.2): PEP 695 aliases bind directly to the
    # acyclic private declarations and never resolve the public p facade.
    type AclPayload = FlextLdifProtocolsBase.Acl | str
    type EntryPayload = FlextLdifProtocolsBase.Entry | str
    type EntryLike = FlextLdifProtocolsBase.Entry
    type EntrySequence = t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]
    type EntryOrEntries = FlextLdifProtocolsBase.Entry | EntrySequence
    type SchemaAttributeLike = FlextLdifProtocolsBase.SchemaAttribute
    type SchemaObjectClassLike = FlextLdifProtocolsBase.SchemaObjectClass
    type SchemaItem = SchemaAttributeLike | SchemaObjectClassLike
    type AclLike = FlextLdifProtocolsBase.Acl
    type AclSequence = t.MutableSequenceOf[AclLike]
    type ConvertedModel = EntryLike | SchemaItem | AclLike
    type SchemaConversionValue = SchemaItem | str
    type EventType = (
        FlextLdifProtocolsBase.ConversionEvent | FlextLdifProtocolsBase.DnEvent
    )
    type ResponseLike = FlextLdifProtocolsBase.Response
    type ParseResponseLike = FlextLdifProtocolsBase.ParseResponse
    type ValidationResultLike = FlextLdifProtocolsBase.ValidationResult
    type MigrationPipelineResultLike = FlextLdifProtocolsBase.MigrationPipelineResult
    type WriteResponseLike = FlextLdifProtocolsBase.WriteResponse
    type ServerServerLike = FlextLdifProtocolsDomain.ServerServer


__all__: list[str] = ["FlextLdifTypesDomain"]
