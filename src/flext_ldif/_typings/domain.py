"""Protocol-based LDIF composite type aliases."""

from __future__ import annotations

from flext_core import FlextTypes as t

from .._protocols.base import FlextLdifProtocolsBase as p
from .._protocols.domain import FlextLdifProtocolsDomain as pd


class FlextLdifTypesDomain:
    """Composite LDIF aliases built from canonical protocols."""

    type AclPayload = p.Acl | str
    type EntryPayload = p.Entry | str
    type EntryLike = p.Entry
    type EntrySequence = t.MutableSequenceOf[p.Entry]
    type EntryOrEntries = p.Entry | EntrySequence
    type SchemaAttributeLike = p.SchemaAttribute
    type SchemaObjectClassLike = p.SchemaObjectClass
    type SchemaItem = SchemaAttributeLike | SchemaObjectClassLike
    type AclLike = p.Acl
    type AclSequence = t.MutableSequenceOf[AclLike]
    type ConvertedModel = EntryLike | SchemaItem | AclLike
    type SchemaConversionValue = SchemaItem | str
    type EventType = p.ConversionEvent | p.DnEvent
    type ResponseLike = p.Response
    type ParseResponseLike = p.ParseResponse
    type ValidationResultLike = p.ValidationResult
    type MigrationPipelineResultLike = p.MigrationPipelineResult
    type WriteResponseLike = p.WriteResponse
    type ServerServerLike = pd.ServerServer


__all__: list[str] = ["FlextLdifTypesDomain"]
