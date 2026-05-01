"""Protocol-based LDIF composite type aliases."""

from __future__ import annotations

from flext_core import t
from flext_ldif import p


class FlextLdifTypesDomain:
    """Composite LDIF aliases built from canonical protocols."""

    type AclPayload = p.Ldif.Acl | str
    type EntryPayload = p.Ldif.Entry | str
    type EntryLike = p.Ldif.Entry
    type EntrySequence = t.MutableSequenceOf[p.Ldif.Entry]
    type EntryOrEntries = p.Ldif.Entry | EntrySequence
    type SchemaAttributeLike = p.Ldif.SchemaAttribute
    type SchemaObjectClassLike = p.Ldif.SchemaObjectClass
    type SchemaItem = SchemaAttributeLike | SchemaObjectClassLike
    type AclLike = p.Ldif.Acl
    type AclSequence = t.MutableSequenceOf[AclLike]
    type ConvertedModel = EntryLike | SchemaItem | AclLike
    type SchemaConversionValue = SchemaItem | str
    type EventType = p.Ldif.ConversionEvent | p.Ldif.DnEvent
    type ResponseLike = p.Ldif.Response
    type ParseResponseLike = p.Ldif.ParseResponse
    type ValidationResultLike = p.Ldif.ValidationResult
    type MigrationPipelineResultLike = p.Ldif.MigrationPipelineResult
    type WriteResponseLike = p.Ldif.WriteResponse
    type ServerQuirkLike = p.Ldif.ServerQuirk


__all__: list[str] = ["FlextLdifTypesDomain"]
