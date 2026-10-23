"""Protocol-based LDIF composite type aliases.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import t

from flext_ldif import FlextLdifProtocols


class FlextLdifTypesDomain:
    """Composite LDIF aliases built from canonical protocols."""

    type AclPayload = FlextLdifProtocols.Ldif.Acl | str
    type EntryPayload = FlextLdifProtocols.Ldif.Entry | str
    type EntryLike = FlextLdifProtocols.Ldif.Entry
    type EntrySequence = t.MutableSequenceOf[FlextLdifProtocols.Ldif.Entry]
    type EntryOrEntries = FlextLdifProtocols.Ldif.Entry | EntrySequence
    type SchemaAttributeLike = FlextLdifProtocols.Ldif.SchemaAttribute
    type SchemaObjectClassLike = FlextLdifProtocols.Ldif.SchemaObjectClass
    type SchemaItem = SchemaAttributeLike | SchemaObjectClassLike
    type AclLike = FlextLdifProtocols.Ldif.Acl
    type AclAttributeNames = frozenset[str]
    type AclSequence = t.MutableSequenceOf[AclLike]
    type ConvertedModel = EntryLike | SchemaItem | AclLike
    type SchemaConversionValue = SchemaItem | str
    type EventType = (
        FlextLdifProtocols.Ldif.ConversionEvent | FlextLdifProtocols.Ldif.DnEvent
    )
    type ResponseLike = FlextLdifProtocols.Ldif.Response
    type ParseResponseLike = FlextLdifProtocols.Ldif.ParseResponse
    type ValidationResultLike = FlextLdifProtocols.Ldif.ValidationResult
    type MigrationPipelineResultLike = FlextLdifProtocols.Ldif.MigrationPipelineResult
    type WriteResponseLike = FlextLdifProtocols.Ldif.WriteResponse
    type ServerServerLike = FlextLdifProtocols.Ldif.ServerServer


__all__: list[str] = ["FlextLdifTypesDomain"]
