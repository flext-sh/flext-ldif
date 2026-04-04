"""Protocol-based LDIF composite type aliases."""

from __future__ import annotations

from collections.abc import Callable, MutableSequence

from flext_ldif import FlextLdifProtocols as p


class FlextLdifTypesDomain:
    """Composite LDIF aliases built from canonical protocols."""

    type DnLike = str | p.Ldif.DN
    type DnRegistryLike = p.Ldif.DnRegistry
    type EntryLike = p.Ldif.Entry
    type EntrySequence = MutableSequence[p.Ldif.Entry]
    type EntryOrEntries = p.Ldif.Entry | EntrySequence
    type EntryPredicate = Callable[[p.Ldif.Entry], bool]
    type EntryTransformHook = Callable[
        [p.Ldif.Entry],
        p.Ldif.Entry,
    ]
    type EntryWriteHook = Callable[[p.Ldif.Entry], p.Result[str]]
    type EntryCommentsHook = Callable[
        [p.Ldif.Entry, MutableSequence[str]],
        None,
    ]
    type ParseDnHook = Callable[[str], str | None]
    type ParseOidHook = Callable[[str], str | None]
    type SchemaAttributeLike = p.Ldif.SchemaAttribute
    type SchemaObjectClassLike = p.Ldif.SchemaObjectClass
    type SchemaItem = SchemaAttributeLike | SchemaObjectClassLike
    type SchemaItemSequence = MutableSequence[SchemaItem]
    type AclLike = p.Ldif.Acl
    type WriteOptionsLike = p.Ldif.WriteFormatOptions | p.Ldif.WriteOptions
    type MetadataLike = (
        p.Ldif.QuirkMetadata
        | p.Ldif.DynamicMetadata
        | p.Ldif.ValidationMetadata
        | p.Ldif.SchemaFormatDetails
        | p.Ldif.FormatDetails
    )
    type ConvertedModel = EntryLike | SchemaItem | AclLike
    type SchemaConversionValue = SchemaItem | str
    type EventType = p.Ldif.ConversionEvent | p.Ldif.DnEvent
    type EventSequence = MutableSequence[EventType]
    type ParseResponseLike = p.Ldif.ParseResponse
    type ValidationResultLike = p.Ldif.ValidationResult
    type MigrationPipelineResultLike = p.Ldif.MigrationPipelineResult
    type WriteResponseLike = p.Ldif.WriteResponse
    type SchemaQuirkLike = p.Ldif.SchemaQuirk
    type AclQuirkLike = p.Ldif.AclQuirk
    type EntryQuirkLike = p.Ldif.EntryQuirk
    type QuirkRegistryLike = p.Ldif.QuirkRegistry
    type SchemaItemResult = p.Result[SchemaItem]
    type SchemaAttributeResult = p.Result[SchemaAttributeLike]
    type SchemaObjectClassResult = p.Result[SchemaObjectClassLike]
    type EntryResult = p.Result[EntryLike]
    type EntrySequenceResult = p.Result[EntrySequence]
    type AclResult = p.Result[AclLike]
    type WriteStringResult = p.Result[str]
    type ParseResponseResult = p.Result[ParseResponseLike]
    type ValidationResponseResult = p.Result[ValidationResultLike]
    type MigrationResult = p.Result[MigrationPipelineResultLike]
    type WriteResponseResult = p.Result[WriteResponseLike]


__all__ = ["FlextLdifTypesDomain"]
